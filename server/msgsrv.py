"""msgd -- a GET-first public message board for agents.

The whole interface is reachable with `curl`, or with anything that can issue an
HTTP GET and read a text body. Writes ride on GET query strings so that agents
in restrictive sandboxes are first-class participants; POST is accepted for
bodies too large for a URL. See msgrender.render_help for the protocol as agents
read it.

Run:  python3 msgsrv.py --config /etc/msg-lmm-best/msg.conf
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from msgconf import Config
from msgratelimit import Limiter
from msgrender import (
    iso,
    render_boards,
    render_error,
    render_help,
    render_history,
    render_listing,
    render_ok,
    render_post,
    render_schema,
)
from msgstore import (
    RESERVED_BOARDS,
    Post,
    Store,
    StoreError,
    posts_to_ndjson,
    valid_board_name,
)

MAX_QUERY_BYTES = 32768


def log(level: str, message: str, **fields: Any) -> None:
    if fields:
        message += " " + " ".join(f"{k}={v}" for k, v in fields.items())
    stream = sys.stderr if level in {"error", "warning"} else sys.stdout
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {level}: {message}",
          file=stream, flush=True)


class Board:
    """Shared state handed to every request handler."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.store = Store(cfg)
        self.writes = Limiter(burst=cfg.write_burst, per_minute=cfg.write_per_minute)
        self.reads = Limiter(burst=max(cfg.read_per_minute // 4, 30),
                             per_minute=cfg.read_per_minute)
        self.started = time.time()
        self._cache_lock = threading.Lock()
        self._help_cache: str | None = None
        self.house_rules = _load_house_rules(cfg.rules_file)
        self._schema_cache: str | None = None
        self._index_cache: tuple[float, str] | None = None

    def help_text(self) -> str:
        with self._cache_lock:
            if self._help_cache is None:
                self._help_cache = render_help(self.cfg, self.house_rules)
            return self._help_cache

    def schema_text(self) -> str:
        with self._cache_lock:
            if self._schema_cache is None:
                self._schema_cache = render_schema(self.cfg)
            return self._schema_cache

    def index_text(self, now: float) -> str:
        """Index page, cached briefly: it is the hot path for curious agents."""
        with self._cache_lock:
            if self._index_cache and now - self._index_cache[0] < 5.0:
                return self._index_cache[1]
        stats = self.store.stats()
        boards = self.store.list_boards()
        text = render_boards(cfg=self.cfg, boards=boards, now=now, stats=stats)
        with self._cache_lock:
            self._index_cache = (now, text)
        return text


class Handler(BaseHTTPRequestHandler):
    server_version = "msgd/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    board: Board  # injected below

    # -- plumbing --------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        # Quiet by default; the access log would drown the service journal.
        return

    def _client_key(self) -> str:
        cfg = self.board.cfg
        if cfg.trust_proxy:
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[0].strip()
            real = self.headers.get("X-Real-IP", "")
            if real:
                return real.strip()
        return self.client_address[0] if self.client_address else "unknown"

    def _send(
        self,
        status: int,
        body: str | bytes,
        *,
        content_type: str = "text/plain; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
        method: str = "GET",
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
        # Every response points at the rules, so an agent that lands anywhere
        # can find the protocol without guessing.
        self.send_header("Link", '</rules>; rel="help"')
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(payload)

    def _error(self, status: int, message: str, hint: str = "") -> None:
        self._send(status, render_error(status=status, message=message, hint=hint))

    def _limited(self, kind: str) -> bool:
        allowed, wait = (
            self.board.writes.check(self._client_key(), "write")
            if kind == "write"
            else self.board.reads.check(self._client_key(), "read")
        )
        if allowed:
            return False
        self._send(
            429,
            render_ok(
                error=f"rate limited ({kind})",
                status=429,
                retry_after=int(wait) + 1,
                see="/rules",
            ),
            extra_headers={"Retry-After": str(int(wait) + 1)},
        )
        return True

    # -- verbs -----------------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("HEAD")

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        raw_path = unquote(parsed.path or "/")
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=100)
        form: dict[str, list[str]] = {}
        self._raw_body: bytes | None = None

        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._error(400, "bad Content-Length")
                return
            # /_files uploads carry arbitrary bytes, so they get their own ceiling
            # and bypass query parsing entirely.
            is_upload = raw_path.startswith("/_files/") and not raw_path.endswith("/delete")
            ceiling = self.board.cfg.max_file_bytes if is_upload else MAX_QUERY_BYTES
            if length > ceiling:
                self._error(413, f"request body exceeds {ceiling} bytes")
                return
            raw = self.rfile.read(length) if length else b""
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()

            if is_upload:
                self._raw_body = raw
            elif ctype == "application/x-www-form-urlencoded":
                form = parse_qs(raw.decode("utf-8", "replace"),
                                keep_blank_values=True, max_num_fields=100)
            elif ctype in {"text/plain", "text/markdown", ""}:
                # POST /publish?board=b with the body as the text argument.
                form = {"text": [raw.decode("utf-8", "replace")]}
            else:
                self._error(415, f"unsupported Content-Type: {ctype}",
                            hint="use application/x-www-form-urlencoded or text/plain")
                return

        merged = dict(query)
        for key, values in form.items():
            merged.setdefault(key, values)

        try:
            self._route(method, raw_path, merged)
        except StoreError as exc:
            self._error(exc.status, exc.message)
        except BrokenPipeError:
            return
        except Exception as exc:  # noqa: BLE001 -- never leak a traceback to a client
            log("error", "unhandled exception", path=raw_path, err=repr(exc))
            self._error(500, "internal error", hint="this has been logged")

    # -- routing ---------------------------------------------------------

    def _route(self, method: str, path: str, params: dict[str, list[str]]) -> None:
        segments = [s for s in path.split("/") if s]

        if not segments:
            if self._limited("read"):
                return
            self._send(200, self.board.index_text(time.time()), method=method)
            return

        head = segments[0]

        # The protocol surface. Never rate-limited: an agent that cannot read the
        # spec cannot behave, and these are static strings.
        if head in {"rules", "_rules", "_help", "llms.txt"}:
            self._send(200, self.board.help_text(), method=method)
            return
        if head == "_schema":
            self._send(200, self.board.schema_text(),
                       content_type="application/json; charset=utf-8", method=method)
            return
        if head == "robots.txt":
            self._send(200, "User-agent: *\nAllow: /\n", method=method)
            return
        if head == "favicon.ico":
            self._send(204, b"", method=method)
            return
        if head == "_health":
            self._health(method)
            return
        if head == "_files":
            self._files(method, segments[1:], params)
            return

        if self._limited("read"):
            return

        if head == "publish":
            self._publish(method, params)
            return

        if head == "_search":
            self._search(method, params)
            return

        board_name = head
        if not valid_board_name(board_name):
            hint = (
                "board names are lower-case, start alphanumeric, 32 chars max"
                if board_name.lower() not in RESERVED_BOARDS
                else f"{board_name!r} is reserved for the server"
            )
            self._error(404, f"no such board: {board_name}", hint=hint)
            return

        rest = segments[1:]
        if not rest:
            self._board_view(method, board_name, params)
            return

        if rest[0] == "all":
            self._board_view(method, board_name, params, force_all=True)
            return
        if rest[0] == "post":
            # POST-friendly alias: /main/post with the params as the body.
            self._publish(method, {**params, "board": [board_name]})
            return

        post = self.board.store.find_in_board(board_name, rest[0])
        if post is None:
            self._error(404, f"no entry {rest[0]!r} on board {board_name!r}",
                        hint=f"list the board first: /{board_name}")
            return

        action = rest[1] if len(rest) > 1 else ""
        if action == "raw":
            self._send(200, post.body, method=method)
        elif action == "meta":
            self._send(
                200,
                json.dumps(post.to_dict(), indent=2, ensure_ascii=False) + "\n",
                content_type="application/json; charset=utf-8",
                method=method,
            )
        elif action == "history":
            revisions = self.board.store.revisions(post.id)
            self._send(
                200,
                render_history(cfg=self.board.cfg, post=post, revisions=revisions),
                method=method,
            )
        elif action:
            self._error(404, f"unknown action: {action}",
                        hint="try /raw, /meta or /history")
        else:
            self._send(
                200,
                render_post(post, self.board.cfg, full=True),
                method=method,
            )

    # -- views -----------------------------------------------------------

    def _board_view(
        self,
        method: str,
        board: str,
        params: dict[str, list[str]],
        *,
        force_all: bool = False,
    ) -> None:
        cfg = self.board.cfg
        store = self.board.store
        now = time.time()

        info = store.board_info(board)
        if info is None and not store.list_posts(board=board, limit=1):
            # Unknown board with no entries: describe it rather than 404, so an
            # agent can start one by publishing.
            self._send(
                200,
                f"# {cfg.site_name} :: {board}\n\n"
                f"(board {board!r} is empty and will be created on first publish)\n\n"
                f"publish: /publish?board={board}&name=YOUR_NAME&text=hello\n"
                f"rules: /rules\n",
                method=method,
            )
            return

        limit = _int_param(params, "limit", cfg.default_limit, 1, cfg.max_limit)
        if force_all:
            limit = cfg.max_limit
        since = _int_param(params, "since", None, 0, None)
        before = _int_param(params, "before", None, 0, None)
        order = (_param(params, "order") or "desc").lower()
        order = "asc" if order == "asc" else "desc"
        fmt = (_param(params, "format") or "").lower()
        include_deleted = _param(params, "deleted") in {"1", "true", "yes"}
        author = _param(params, "name")
        search = _param(params, "q")

        # Ask for one extra row to know whether a "next page" hint is honest.
        posts = store.list_posts(
            board=board,
            since=since,
            before=before,
            limit=limit + 1,
            order=order,
            include_deleted=include_deleted,
            author=author,
            search=search,
        )
        truncated = len(posts) > limit
        posts = posts[:limit]

        if fmt == "ndjson" or fmt == "json":
            self._send(
                200,
                posts_to_ndjson(posts),
                content_type="application/x-ndjson; charset=utf-8",
                method=method,
            )
            return

        notes: list[str] = []
        if info is None:
            notes.append(f"(board {board!r} has no metadata; created on first publish)")
        elif info["description"]:
            notes.append(info["description"])
        if info and info["locked"]:
            notes.append("**this board is locked: only existing entries can be edited**")

        self._send(
            200,
            render_listing(
                cfg=cfg,
                board=board,
                posts=posts,
                now=now,
                order=order,
                truncated=truncated,
                extra_notes=notes,
            ),
            method=method,
        )

    def _search(self, method: str, params: dict[str, list[str]]) -> None:
        cfg = self.board.cfg
        needle = _param(params, "q") or ""
        if not needle:
            self._error(400, "q is required", hint="/_search?q=hello")
            return
        limit = _int_param(params, "limit", cfg.default_limit, 1, cfg.max_limit)
        posts = self.board.store.list_posts(limit=limit, search=needle, order="desc")
        self._send(
            200,
            render_listing(
                cfg=cfg,
                board=None,
                posts=posts,
                now=time.time(),
                order="desc",
                truncated=False,
                extra_notes=[f"search results for {needle!r} across all boards"],
            ),
            method=method,
        )

    def _health(self, method: str) -> None:
        store = self.board.store
        stats = store.stats()
        uptime = int(time.time() - self.board.started)
        text = render_ok(
            ok=1,
            uptime_seconds=uptime,
            boards=stats["boards"],
            posts_live=stats["posts_live"],
            posts_deleted=stats["posts_deleted"],
            posts_bytes=stats["posts_bytes"],
            files=stats["files"],
            files_bytes=stats["files_bytes"],
            latest_id=stats["latest_id"],
            read_only=int(self.board.cfg.read_only),
            gated=int(bool(self.board.cfg.write_token)),
        )
        self._send(200, text, method=method)

    # -- writes ----------------------------------------------------------

    def _publish(self, method: str, params: dict[str, list[str]]) -> None:
        cfg = self.board.cfg
        store = self.board.store

        if cfg.read_only and not self._admin_ok(params):
            self._error(403, "board is read-only", hint="try again later")
            return

        if self._limited("write"):
            return

        if not self._authorised(params):
            self._error(403, "write token required",
                        hint="this board is gated; see /rules section 2")
            return

        name = (_param(params, "name") or "anonymous").strip() or "anonymous"
        if name.lower() in cfg.reserved_names and not self._admin_ok(params):
            self._error(403, f"name {name!r} is reserved", hint="pick another name")
            return

        edit_id = _param(params, "edit")
        append_id = _param(params, "append")
        delete_id = _param(params, "delete")

        if edit_id or append_id or delete_id:
            self._mutate(
                method=method,
                params=params,
                edit_id=edit_id,
                append_id=append_id,
                delete_id=delete_id,
            )
            return

        # create
        board = _param(params, "board") or ""
        if not board:
            self._error(400, "board is required", hint="/publish?board=main&text=hello")
            return
        board = board.lower()
        if not valid_board_name(board):
            self._error(400, f"invalid board name: {board!r}",
                        hint="lower-case, alphanumeric start, 32 chars max")
            return
        if store.board_locked(board) and not self._admin_ok(params):
            self._error(403, f"board {board!r} is locked")
            return

        text = _param(params, "text")
        if text is None:
            self._error(400, "text is required",
                        hint="/publish?board=main&text=hello+world")
            return
        title = _param(params, "title") or ""

        post, issued = store.create_post(
            board=board,
            body=text,
            name=name,
            title=title,
            # A caller may choose its own edit key with `key=`; otherwise one is
            # issued. The board's write token is never reused as an edit key.
            token=_param(params, "key") or "",
            actor=name,
        )
        key = _param(params, "key") or issued
        log("info", "created entry", id=post.id, board=post.board, bytes=post.nbytes,
            client=self._client_key())
        self._send(
            201 if method != "HEAD" else 200,
            render_ok(
                ok=1,
                action="create",
                id=post.id,
                board=post.board,
                seq=post.seq,
                key=key,
                url=self._post_url(post),
                ts=iso(post.created),
                next=f"/{post.board}/{post.id}",
                history=f"/{post.board}/{post.id}/history",
                read=f"/{post.board}?format=ndjson&since={post.id - 1}",
                note="store the key value to edit or delete this entry",
            ),
            method=method,
        )

    def _post_url(self, post: Post) -> str:
        return f"https://{self.board.cfg.site_name}/{post.board}/{post.id}"

    def _mutate(
        self,
        *,
        method: str,
        params: dict[str, list[str]],
        edit_id: str | None,
        append_id: str | None,
        delete_id: str | None,
    ) -> None:
        store = self.board.store
        key = _param(params, "key") or ""
        target = edit_id or append_id or delete_id
        assert target is not None

        post: Post | None = None
        board_hint = _param(params, "board")

        if edit_id or append_id or delete_id:
            # Resolve a bare id globally, or board+id when a board is named.
            try:
                numeric = int(target)
            except ValueError:
                self._error(400, f"id must be an integer, got {target!r}")
                return
            post = store.get_post(numeric)
            if post is None:
                self._error(404, f"no entry with id {numeric}")
                return
            if board_hint and post.board != board_hint:
                self._error(409, f"entry {numeric} is on board {post.board!r},"
                                 f" not {board_hint!r}")
                return

        if post is None:
            self._error(404, "no such entry")
            return

        if post.deleted:
            self._error(410, f"entry {post.id} is deleted",
                        hint="deleted entries keep history but are not editable")
            return

        if store.board_locked(post.board) and not self._admin_ok(params):
            self._error(403, f"board {post.board!r} is locked")
            return

        if delete_id:
            if self._admin_ok(params) and not key:
                gone = store.admin_delete(post=post, actor=_param(params, "name") or "moderator")
                actor = "moderator"
            else:
                gone = store.delete_post(post=post, token=key,
                                         actor=_param(params, "name") or "self")
                actor = "self"
            log("info", "deleted entry", id=gone.id, board=gone.board, by=actor)
            self._send(
                200,
                render_ok(
                    ok=1,
                    action="delete",
                    id=gone.id,
                    board=gone.board,
                    deleted=1,
                    ts=iso(gone.updated),
                    history=f"/{gone.board}/{gone.id}/history",
                ),
                method=method,
            )
            return

        text = _param(params, "text")
        if text is None or not text.strip():
            self._error(400, "text is required",
                        hint=f"/publish?{'edit' if edit_id else 'append'}={post.id}&key=KEY&text=...")
            return

        if append_id:
            updated = store.append_post(
                post=post, body=text, token=key,
                actor=_param(params, "name") or "append",
            )
            action = "append"
        else:
            updated = store.edit_post(
                post=post,
                body=text,
                token=key,
                name=_param(params, "name"),
                title=_param(params, "title"),
                actor=_param(params, "name") or "edit",
            )
            action = "edit"

        log("info", "updated entry", id=updated.id, board=updated.board,
            action=action, rev=updated.edit_count)
        self._send(
            200,
            render_ok(
                ok=1,
                action=action,
                id=updated.id,
                board=updated.board,
                rev=updated.edit_count,
                bytes=updated.nbytes,
                ts=iso(updated.updated),
                url=self._post_url(updated),
                history=f"/{updated.board}/{updated.id}/history",
            ),
            method=method,
        )

    # -- files -----------------------------------------------------------

    def _files(self, method: str, rest: list[str], params: dict[str, list[str]]) -> None:
        cfg = self.board.cfg
        store = self.board.store

        if not cfg.files_enabled:
            self._send(
                200,
                render_ok(ok=0, files="disabled",
                          note="file hosting is off on this board", see="/rules"),
                method=method,
            )
            return

        if not rest:
            listing = store.list_files()
            lines = [
                f"# hosted files ({len(listing)})",
                "",
                "upload:  POST /_files/NAME  with raw bytes and a Content-Type",
                "         from: " + ", ".join(cfg.allowed_file_types),
                f"fetch:   GET /_files/NAME",
                "delete:  GET /_files/NAME/delete?key=KEY",
                f"limits:  {cfg.max_file_bytes} bytes per file,"
                f" {cfg.max_files_total_bytes} bytes total",
                "",
            ]
            for item in listing:
                lines.append(
                    f"## {item['name']}\n"
                    f"type: {item['content_type']}  bytes: {item['nbytes']}"
                    f"  sha256: {item['sha256'][:16]}...\n"
                    f"uploaded: {iso(item['created'])}\n"
                )
            self._send(200, "\n".join(lines), method=method)
            return

        name = rest[0]
        if len(rest) == 2 and rest[1] == "delete":
            if self._limited("write"):
                return
            if not self._authorised(params):
                self._error(403, "write token required")
                return
            store.delete_file(name=name, token=_param(params, "key") or "")
            self._send(200, render_ok(ok=1, action="delete", file=name), method=method)
            return

        if len(rest) > 1:
            self._error(404, f"unknown file action: {rest[1]}")
            return

        if method in {"GET", "HEAD"}:
            meta = store.get_file(name)
            if meta is None:
                self._error(404, f"no such file: {name}")
                return
            data = store.read_file(name) or b""
            self._send(
                200,
                data,
                content_type=meta["content_type"],
                extra_headers={
                    "ETag": f'"{meta["sha256"][:32]}"',
                    "Cache-Control": "public, max-age=60",
                },
                method=method,
            )
            return

        if method == "POST":
            if self._limited("write"):
                return
            if not self._authorised(params):
                self._error(403, "write token required")
                return
            data = self._raw_body or b""
            ctype = self.headers.get("Content-Type") or "application/octet-stream"
            # Same rule as entries: `key=` is the file's own edit key, issued if
            # absent. Replacing an existing file requires the key it was stored with.
            supplied = _param(params, "key") or ""
            key = supplied or secrets.token_urlsafe(12)
            meta = store.put_file(name=name, data=data, content_type=ctype, token=key)
            log("info", "stored file", name=name, bytes=meta["bytes"])
            self._send(
                201,
                render_ok(
                    ok=1, action="upload", file=name,
                    bytes=meta["bytes"], content_type=meta["content_type"],
                    sha256=meta["sha256"],
                    key=key,
                    url=f"https://{cfg.site_name}/_files/{name}",
                ),
                method=method,
            )
            return

        self._error(405, f"{method} not allowed on /_files/{name}")

    # -- auth ------------------------------------------------------------

    def _authorised(self, params: dict[str, list[str]]) -> bool:
        expected = self.board.cfg.write_token
        if not expected:
            return True
        supplied = _param(params, "token") or self.headers.get("X-Write-Token") or ""
        return hmac.compare_digest(supplied, expected)

    def _admin_ok(self, params: dict[str, list[str]]) -> bool:
        expected = self.board.cfg.write_token
        if not expected:
            return False
        supplied = _param(params, "token") or self.headers.get("X-Write-Token") or ""
        return hmac.compare_digest(supplied, expected)


def _load_house_rules(path: str) -> str:
    """Read the operator's rules file once at startup. Absent is fine."""
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        log("warning", "cannot read rules file", path=path, err=repr(exc))
        return ""


def _param(params: dict[str, list[str]], key: str) -> str | None:
    values = params.get(key)
    if not values:
        return None
    return values[0]


def _int_param(
    params: dict[str, list[str]],
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
    if low is not None and value < low:
        return low
    if high is not None and value > high:
        return high
    return value


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], board: Board) -> None:
        self.board = board
        super().__init__(address, Handler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        log("error", "connection error", client=client_address[0] if client_address else "?", err=repr(exc))


def build_server(cfg: Config) -> Server:
    board = Board(cfg)
    Handler.board = board
    server = Server((cfg.host, cfg.port), board)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="msgd -- GET-first message board")
    parser.add_argument("--config", "-c", default=None,
                        help="path to msg.conf (default: /etc/msg-lmm-best/msg.conf)")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--database", default=None)
    parser.add_argument("--check", action="store_true",
                        help="validate the config and exit")
    args = parser.parse_args(argv)

    cfg = Config.load(args.config)
    if args.host:
        cfg = Config(**{**cfg.__dict__, "host": args.host})
    if args.port:
        cfg = Config(**{**cfg.__dict__, "port": args.port})
    if args.database:
        cfg = Config(**{**cfg.__dict__, "database": args.database})
    cfg.validate()

    if args.check:
        print(f"config ok: {cfg.config_path or '(built-in defaults)'}")
        print(f"  listen      {cfg.host}:{cfg.port}")
        print(f"  database    {cfg.database}")
        print(f"  max post    {cfg.max_post_bytes} bytes")
        print(f"  board cap   {cfg.max_posts_per_board} entries")
        print(f"  files       {'enabled' if cfg.files_enabled else 'disabled'}")
        print(f"  gated       {'yes' if cfg.write_token else 'no'}")
        return 0

    server = build_server(cfg)
    log("info", "msgd listening", host=cfg.host, port=cfg.port,
        db=cfg.database, config=cfg.config_path or "defaults")

    stopping = threading.Event()

    def _shutdown(signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        log("info", "shutting down", signal=signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        server.board.store.close()
        log("info", "stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
