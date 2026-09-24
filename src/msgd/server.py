"""HTTP server for msgd."""

from __future__ import annotations

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlparse

from msgd import __version__
from msgd.config import Config
from msgd.ratelimit import Limiter
from msgd.render import (
    posts_to_ndjson,
    render_error,
    render_index,
    render_listing,
    render_ok,
    render_post,
    render_rules,
    render_schema,
)
from msgd.store import RESERVED_BOARDS, Store, StoreError, valid_board_name

Params = dict[str, list[str]]
MAX_REQUEST_BYTES = 65_536


def log(level: str, message: str, **fields: Any) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in fields.items())
    print(
        f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {level}: "
        f"{message}{' ' + suffix if suffix else ''}",
        file=sys.stderr if level == "error" else sys.stdout,
        flush=True,
    )


class Board:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.store = Store(cfg)
        self.reads = Limiter(
            burst=max(30, cfg.read_per_minute // 4),
            per_minute=cfg.read_per_minute,
        )
        self.writes = Limiter(
            burst=cfg.write_burst,
            per_minute=cfg.write_per_minute,
        )
        self.started = time.time()


class MsgServer(ThreadingHTTPServer):
    """Threading HTTP server with typed shared board state."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        board: Board,
    ) -> None:
        self.board = board
        super().__init__(server_address, handler_class)


class Handler(BaseHTTPRequestHandler):
    server_version = f"msgd/{__version__}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def board(self) -> Board:
        return cast(MsgServer, self.server).board

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _client(self) -> str:
        if self.board.cfg.trust_proxy:
            if value := self.headers.get("X-Forwarded-For"):
                return value.split(",", 1)[0].strip()
            if value := self.headers.get("X-Real-IP"):
                return value.strip()
        return self.client_address[0] if self.client_address else "unknown"

    def _send(
        self,
        status: int,
        body: str | bytes,
        *,
        content_type: str = "text/plain; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", self.board.cfg.cors_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Link", '</rules>; rel="help"')
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _error(self, status: int, message: str, hint: str = "") -> None:
        self._send(status, render_error(status, message, hint))

    def _limited(self, write: bool) -> bool:
        limiter = self.board.writes if write else self.board.reads
        allowed, wait = limiter.check(self._client())
        if allowed:
            return False
        retry_after = int(wait) + 1
        self._send(
            429,
            render_ok(error="rate limited", status=429, retry_after=retry_after),
            extra_headers={"Retry-After": str(retry_after)},
        )
        return True

    def do_OPTIONS(self) -> None:
        self._send(204, b"")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path or "/")
        params = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=50)

        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._error(400, "bad Content-Length")
                return
            if length < 0 or length > MAX_REQUEST_BYTES:
                self._error(413, "request too large")
                return

            raw = self.rfile.read(length) if length else b""
            content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip()
            if content_type == "application/x-www-form-urlencoded":
                form = parse_qs(
                    raw.decode("utf-8", "replace"),
                    keep_blank_values=True,
                    max_num_fields=50,
                )
            elif content_type in {"text/plain", "text/markdown", ""}:
                form = {"text": [raw.decode("utf-8", "replace")]}
            else:
                self._error(415, f"unsupported Content-Type: {content_type}")
                return

            for key, values in form.items():
                params.setdefault(key, values)

        try:
            self._route(method, path, params)
        except StoreError as exc:
            self._error(exc.status, exc.message, exc.hint)
        except BrokenPipeError:
            return
        except Exception as exc:
            log("error", "unhandled exception", path=path, error=repr(exc))
            self._error(500, "internal error")

    def _route(self, method: str, path: str, params: Params) -> None:
        segments = [segment for segment in path.split("/") if segment]
        head = segments[0] if segments else ""

        if head in {"rules", "_rules", "_help", "llms.txt"}:
            self._send(200, render_rules(self.board.cfg))
            return
        if head == "_schema":
            self._send(
                200,
                render_schema(self.board.cfg),
                content_type="application/json; charset=utf-8",
            )
            return
        if head == "robots.txt":
            self._send(200, "User-agent: *\nAllow: /\n")
            return
        if head == "favicon.ico":
            self._send(204, b"")
            return

        if head == "publish":
            if method == "HEAD":
                self._send(
                    405,
                    render_error(405, "HEAD cannot write"),
                    extra_headers={"Allow": "GET, POST"},
                )
                return
            if self._limited(True):
                return
            self._publish(params)
            return

        if self._limited(False):
            return

        if not head:
            stats = self.board.store.stats()
            self._send(
                200,
                render_index(
                    self.board.cfg,
                    self.board.store.list_boards(),
                    stats,
                ),
            )
            return
        if head == "_health":
            self._send(
                200,
                render_ok(
                    ok=1,
                    version=__version__,
                    uptime_seconds=int(time.time() - self.board.started),
                    **self.board.store.stats(),
                ),
            )
            return
        if head == "_search":
            self._search(params)
            return

        if not valid_board_name(head):
            hint = (
                f"{head!r} is reserved"
                if head in RESERVED_BOARDS
                else "board names are lower-case and 32 chars max"
            )
            self._error(404, f"no such board: {head}", hint)
            return

        if len(segments) == 1:
            self._board_view(head, params)
            return

        if len(segments) == 2 and segments[1] == "post":
            if method == "HEAD":
                self._send(
                    405,
                    render_error(405, "HEAD cannot write"),
                    extra_headers={"Allow": "GET, POST"},
                )
                return
            if self._limited(True):
                return
            self._publish({**params, "board": [head]})
            return

        post = self.board.store.find_in_board(head, segments[1])
        if post is None:
            self._error(404, f"no entry {segments[1]!r} on /{head}")
            return

        action = segments[2] if len(segments) > 2 else ""
        if not action:
            self._send(200, render_post(post))
        elif action == "raw":
            self._send(200, post.body)
        elif action == "meta":
            self._send(
                200,
                json.dumps(post.to_dict(), ensure_ascii=False, indent=2) + "\n",
                content_type="application/json; charset=utf-8",
            )
        else:
            self._error(404, f"unknown action: {action}", "try /raw or /meta")

    def _board_view(self, board: str, params: Params) -> None:
        info = self.board.store.board_info(board)
        if info is None:
            self._send(
                200,
                f"# /{board} · empty\n\n"
                f"create it: /publish?board={board}&name=YOU&text=hello\n",
            )
            return

        limit = _int(
            params,
            "limit",
            self.board.cfg.default_limit,
            1,
            self.board.cfg.max_limit,
        )
        assert limit is not None

        posts = self.board.store.list_posts(
            board=board,
            since=_int(params, "since", None, 0, None),
            before=_int(params, "before", None, 0, None),
            limit=limit + 1,
            order="asc" if (_param(params, "order") or "").lower() == "asc" else "desc",
            author=_param(params, "name"),
            search=_param(params, "q"),
        )
        truncated = len(posts) > limit
        posts = posts[:limit]

        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(posts),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return

        self._send(
            200,
            render_listing(
                board=board,
                posts=posts,
                full=(_param(params, "view") or "").lower() == "full",
                truncated=truncated,
                note=info["description"],
            ),
        )

    def _search(self, params: Params) -> None:
        needle = _param(params, "q") or ""
        if not needle:
            self._error(400, "q is required", "/_search?q=hello")
            return

        limit = _int(
            params,
            "limit",
            self.board.cfg.default_limit,
            1,
            self.board.cfg.max_limit,
        )
        assert limit is not None

        posts = self.board.store.list_posts(search=needle, limit=limit + 1)
        self._send(
            200,
            render_listing(
                board=None,
                posts=posts[:limit],
                full=(_param(params, "view") or "").lower() == "full",
                truncated=len(posts) > limit,
                note=f"search: {needle!r}",
            ),
        )

    def _publish(self, params: Params) -> None:
        store = self.board.store
        edit = _param(params, "edit")
        delete = _param(params, "delete")

        if edit is not None and delete is not None:
            raise StoreError("choose exactly one of edit or delete", 400)

        if edit is not None:
            post_id = _post_id(edit, "edit")
            post = store.get_post(post_id)
            if post is None:
                raise StoreError(f"no entry {post_id}", 404)

            text = _param(params, "text")
            if text is None:
                raise StoreError("text is required", 400)

            updated = store.edit_post(
                post=post,
                body=text,
                name=_param(params, "name"),
                title=_param(params, "title"),
            )
            self._send(
                200,
                render_ok(
                    ok=1,
                    action="edit",
                    id=updated.id,
                    board=updated.board,
                    bytes=updated.nbytes,
                    url=f"https://{self.board.cfg.site_name}/{updated.board}/{updated.id}",
                ),
            )
            return

        if delete is not None:
            post_id = _post_id(delete, "delete")
            if not store.delete_post(post_id):
                raise StoreError(f"no entry {post_id}", 404)
            self._send(200, render_ok(ok=1, action="delete", id=post_id))
            return

        board = (_param(params, "board") or "").lower()
        if not board:
            raise StoreError("board is required", 400, "/publish?board=main&text=hello")

        text = _param(params, "text")
        if text is None:
            raise StoreError("text is required", 400)

        post, evicted = store.create_post(
            board=board,
            body=text,
            name=_param(params, "name") or "anonymous",
            title=_param(params, "title") or "",
        )
        self._send(
            201,
            render_ok(
                ok=1,
                action="create",
                id=post.id,
                board=post.board,
                seq=post.seq,
                evicted=evicted or None,
                url=f"https://{self.board.cfg.site_name}/{post.board}/{post.id}",
            ),
        )


def _post_id(value: str, action: str) -> int:
    try:
        post_id = int(value)
    except ValueError as exc:
        raise StoreError(f"{action} requires a numeric id", 400) from exc
    if post_id < 1:
        raise StoreError(f"{action} requires a positive id", 400)
    return post_id


def _param(params: Params, key: str) -> str | None:
    values = params.get(key)
    return values[0] if values else None


def _int(
    params: Params,
    key: str,
    default: int | None,
    low: int | None,
    high: int | None,
) -> int | None:
    raw = _param(params, key)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def build_server(cfg: Config) -> MsgServer:
    board = Board(cfg)
    return MsgServer((cfg.host, cfg.port), Handler, board)
