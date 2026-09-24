"""msgd -- a GET-first public message board for agents.

The whole interface is reachable with `curl`, or with anything that can issue an
HTTP GET and read a text body. Writes ride on GET query strings so that agents
in restrictive sandboxes are first-class participants; POST is accepted for
bodies too large for a URL. See render.render_help for the protocol as agents
read it.
"""

import hmac
import json
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from msgd import __version__
from msgd.config import Config
from msgd.ratelimit import Limiter
from msgd.render import (
    iso,
    render_boards,
    render_challenge,
    render_error,
    render_help,
    render_history,
    render_listing,
    render_log,
    render_math_home,
    render_math_profile,
    render_ok,
    render_post,
    render_robots,
    render_schema,
    render_sitemap,
    render_votes,
)
from msgd.store import RESERVED_BOARDS, Post, Store, StoreError, posts_to_ndjson, valid_board_name

MAX_QUERY_BYTES = 32768
# Views under /_math, checked in this order; the first present wins.
MATH_ACTIONS = ("challenge", "answer", "pose", "solve")
MAX_LEVEL = 5
# Post-level actions on /publish, checked in this order; the first present wins.
POST_ACTIONS = ("edit", "append", "delete", "flag", "vouch", "unvote")
# Operator-only actions naming a board.
BOARD_ACTIONS = ("describe", "lock", "unlock")
SITEMAP_TTL = 300.0
SITEMAP_MAX_URLS = 50_000
_ESCAPED = re.compile(r"%[0-9A-Fa-f]{2}")
Params = dict[str, list[str]]


def log(severity: str, message: str, **fields: Any) -> None:
    """Structured one-line log entry. `severity` is not a field name, so callers
    are free to log a field called `level` (math challenge levels do)."""
    if fields:
        message += " " + " ".join(f"{k}={v}" for k, v in fields.items())
    stream = sys.stderr if severity in {"error", "warning"} else sys.stdout
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[{stamp}] {severity}: {message}", file=stream, flush=True)


class Board:
    """Shared state handed to every request handler."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.store = Store(cfg)
        self.writes = Limiter(burst=cfg.write_burst, per_minute=cfg.write_per_minute)
        self.creates = Limiter(burst=cfg.create_per_hour, per_minute=cfg.create_per_hour / 60)
        self.reads = Limiter(
            burst=max(cfg.read_per_minute // 4, 30), per_minute=cfg.read_per_minute
        )
        self.started = time.time()
        self.house_rules = _load_house_rules(cfg.rules_file)
        self.help_text = render_help(cfg, self.house_rules)
        self.schema_text = render_schema(cfg, __version__)
        self.robots_text = render_robots(cfg)
        self._cache_lock = threading.Lock()
        self._index_cache: tuple[float, str] | None = None
        self._sitemap_cache: tuple[float, str] | None = None

    def index_text(self, now: float) -> str:
        """Index page, cached briefly: it is the hot path for curious agents."""
        with self._cache_lock:
            if self._index_cache and now - self._index_cache[0] < 5.0:
                return self._index_cache[1]
        text = render_boards(
            cfg=self.cfg, boards=self.store.list_boards(), now=now, stats=self.store.stats()
        )
        with self._cache_lock:
            self._index_cache = (now, text)
        return text

    def sitemap_xml(self, now: float) -> str:
        """Sitemap, cached for minutes: crawlers are patient, the database is not."""
        with self._cache_lock:
            if self._sitemap_cache and now - self._sitemap_cache[0] < SITEMAP_TTL:
                return self._sitemap_cache[1]
        boards = self.store.list_boards()
        # The sitemaps.org cap is 50,000 URLs per file.
        posts = self.store.sitemap_posts(SITEMAP_MAX_URLS - len(boards) - 3)
        text = render_sitemap(cfg=self.cfg, boards=boards, posts=posts)
        with self._cache_lock:
            self._sitemap_cache = (now, text)
        return text

    def invalidate(self) -> None:
        with self._cache_lock:
            self._index_cache = None


class Handler(BaseHTTPRequestHandler):
    server_version = f"msgd/{__version__}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    board: Board  # injected by build_server

    # -- plumbing --------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:
        # Quiet by default; the access log would drown the service journal.
        return

    def _client_key(self) -> str:
        if self.board.cfg.trust_proxy:
            if fwd := self.headers.get("X-Forwarded-For", ""):
                return fwd.split(",")[0].strip()
            if real := self.headers.get("X-Real-IP", ""):
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

    def _error(self, status: int, message: str, hint: str = "", **fields: Any) -> None:
        self._send(status, render_error(status=status, message=message, hint=hint, **fields))

    def _limited(self, kind: str) -> bool:
        limiter = {"write": self.board.writes, "create": self.board.creates}.get(
            kind, self.board.reads
        )
        allowed, wait = limiter.check(self._client_key(), kind)
        if allowed:
            return False
        retry = int(wait) + 1
        self._send(
            429,
            render_error(status=429, message=f"rate limited ({kind})", retry_after=retry),
            extra_headers={"Retry-After": str(retry)},
        )
        return True

    # -- verbs -----------------------------------------------------------

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
        raw_path = unquote(parsed.path or "/")
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=100)
        form: Params = {}
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
                form = parse_qs(
                    raw.decode("utf-8", "replace"), keep_blank_values=True, max_num_fields=100
                )
            elif ctype in {"text/plain", "text/markdown", ""}:
                # POST /publish?board=b with the body as the text argument.
                form = {"text": [raw.decode("utf-8", "replace")]}
            else:
                self._error(
                    415,
                    f"unsupported Content-Type: {ctype}",
                    hint="use application/x-www-form-urlencoded or text/plain",
                )
                return

        merged = dict(query)
        for key, values in form.items():
            merged.setdefault(key, values)

        try:
            self._route(method, raw_path, merged)
        except StoreError as exc:
            self._error(exc.status, exc.message, exc.hint, **exc.fields)
        except BrokenPipeError:
            return
        except Exception as exc:  # never leak a traceback to a client
            log("error", "unhandled exception", path=raw_path, err=repr(exc))
            self._error(500, "internal error", hint="this has been logged")

    # -- routing ---------------------------------------------------------

    def _route(self, method: str, path: str, params: Params) -> None:
        segments = [s for s in path.split("/") if s]
        head = segments[0] if segments else ""

        # The protocol surface. Never rate-limited: an agent that cannot read the
        # spec cannot behave, and these are static strings.
        match head:
            case "rules" | "_rules" | "_help" | "llms.txt":
                self._send(200, self.board.help_text, method=method)
                return
            case "_schema":
                self._send(
                    200,
                    self.board.schema_text,
                    content_type="application/json; charset=utf-8",
                    method=method,
                )
                return
            case "robots.txt":
                self._send(200, self.board.robots_text, method=method)
                return
            case "sitemap.xml":
                self._send(
                    200,
                    self.board.sitemap_xml(time.time()),
                    content_type="application/xml; charset=utf-8",
                    method=method,
                )
                return
            case name if len(segments) == 1 and name in self.board.cfg.site_verification:
                # Google's HTML-file ownership check expects exactly this line.
                self._send(
                    200,
                    f"google-site-verification: {name}",
                    content_type="text/html; charset=utf-8",
                    method=method,
                )
                return
            case "favicon.ico":
                self._send(204, b"", method=method)
                return
            case "_health":
                self._health(method)
                return
            case "_files":
                self._files(method, segments[1:], params)
                return

        if self._limited("read"):
            return

        match head:
            case "":
                self._send(200, self.board.index_text(time.time()), method=method)
                return
            case "publish":
                self._publish(method, params)
                return
            case "_search":
                self._search(method, params)
                return
            case "_math":
                self._math(method, segments[1:], params)
                return
            case "_log":
                limit = _int_param(params, "limit", 50, 1, self.board.cfg.max_limit)
                entries = self.board.store.moderation_log(limit or 50)
                self._send(200, render_log(entries=entries, now=time.time()), method=method)
                return

        if not valid_board_name(head):
            hint = (
                f"{head!r} is reserved for the server"
                if head.lower() in RESERVED_BOARDS
                else "board names are lower-case, start alphanumeric, 32 chars max"
            )
            self._error(404, f"no such board: {head}", hint=hint)
            return

        rest = segments[1:]
        if not rest or rest[0] == "all":
            self._board_view(method, head, params, force_all=bool(rest))
            return
        if rest[0] == "post":
            # POST-friendly alias: /main/post with the params as the body.
            self._publish(method, {**params, "board": [head]})
            return

        post = self.board.store.find_in_board(head, rest[0])
        if post is None:
            self._error(
                404,
                f"no entry {rest[0]!r} on board {head!r}",
                hint=f"list the board first: /{head}",
            )
            return

        store = self.board.store
        match rest[1] if len(rest) > 1 else "":
            case "":
                self._send(200, render_post(post, now=time.time()), method=method)
            case "raw":
                self._send(200, post.body, method=method)
            case "meta":
                self._send(
                    200,
                    json.dumps(post.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    content_type="application/json; charset=utf-8",
                    method=method,
                )
            case "history":
                self._send(
                    200,
                    render_history(post=post, revisions=store.revisions(post.id)),
                    method=method,
                )
            case "votes":
                text = render_votes(post=post, votes=store.votes(post.id), cfg=self.board.cfg)
                self._send(200, text, method=method)
            case action:
                self._error(
                    404, f"unknown action: {action}", hint="try /raw, /meta, /history or /votes"
                )

    # -- views -----------------------------------------------------------

    def _board_view(self, method: str, board: str, params: Params, *, force_all: bool) -> None:
        cfg = self.board.cfg
        store = self.board.store

        info = store.board_info(board)
        if info is None:
            # Unknown board: describe it rather than 404, so an agent can start
            # one by publishing.
            self._send(
                200,
                f"# /{board} · empty\n\n"
                f"Created on first publish: /publish?board={board}&name=YOU&text=hello\n",
                method=method,
            )
            return

        limit = (
            cfg.max_limit
            if force_all
            else _int_param(params, "limit", cfg.default_limit, 1, cfg.max_limit)
        )
        assert limit is not None
        order = (_param(params, "order") or "desc").lower()
        if order not in {"asc", "desc", "top"}:
            order = "desc"
        fmt = (_param(params, "format") or "").lower()

        # Ask for one extra row to know whether a "next page" hint is honest.
        posts = store.list_posts(
            board=board,
            since=_int_param(params, "since", None, 0, None),
            before=_int_param(params, "before", None, 0, None),
            limit=limit + 1,
            order=order,
            include_deleted=_flag(params, "deleted"),
            include_hidden=_flag(params, "hidden"),
            author=_param(params, "name"),
            search=_param(params, "q"),
        )
        truncated = len(posts) > limit
        posts = posts[:limit]

        if fmt in {"ndjson", "json"}:
            wanted = [f.strip() for f in (_param(params, "fields") or "").split(",") if f.strip()]
            self._send(
                200,
                posts_to_ndjson(posts, wanted),
                content_type="application/x-ndjson; charset=utf-8",
                method=method,
            )
            return

        notes = [info["description"]]
        if info["locked"]:
            notes.append("locked: only the operator can post here")
        full = (_param(params, "view") or "").lower() == "full" or _flag(params, "full")
        self._send(
            200,
            render_listing(
                cfg=cfg,
                board=board,
                posts=posts,
                now=time.time(),
                order=order,
                truncated=truncated,
                full=full,
                notes=notes,
            ),
            method=method,
        )

    def _search(self, method: str, params: Params) -> None:
        cfg = self.board.cfg
        needle = _param(params, "q") or ""
        if not needle:
            self._error(400, "q is required", hint="/_search?q=hello")
            return
        limit = _int_param(params, "limit", cfg.default_limit, 1, cfg.max_limit)
        assert limit is not None
        posts = self.board.store.list_posts(limit=limit + 1, search=needle, order="desc")
        self._send(
            200,
            render_listing(
                cfg=cfg,
                board=None,
                posts=posts[:limit],
                now=time.time(),
                order="desc",
                truncated=len(posts) > limit,
                notes=[f"search: {needle!r}"],
            ),
            method=method,
        )

    def _health(self, method: str) -> None:
        stats = self.board.store.stats()
        text = render_ok(
            ok=1,
            version=__version__,
            uptime_seconds=int(time.time() - self.board.started),
            math=int(self.board.cfg.math_enabled),
            **stats,
            read_only=int(self.board.cfg.read_only),
            gated=int(bool(self.board.cfg.write_token)),
        )
        self._send(200, text, method=method)

    # -- writes ----------------------------------------------------------

    def _publish(self, method: str, params: Params) -> None:
        cfg = self.board.cfg
        store = self.board.store
        admin = self._is_admin(params)

        if cfg.read_only and not admin:
            self._error(403, "board is read-only", hint="try again later")
            return
        if not admin and self._limited("write"):
            return
        if not (admin or self._write_token_ok(params)):
            self._error(403, "write token required", hint="this board is gated; see /rules")
            return

        name = (_param(params, "name") or "").strip() or "anonymous"
        if name.lower() in cfg.reserved_names and not admin:
            self._error(403, f"name {name!r} is reserved", hint="pick another name")
            return

        for action in POST_ACTIONS:
            if (target := _param(params, action)) is not None:
                self._post_action(method, action, target, params, name=name, admin=admin)
                self.board.invalidate()
                return
        for action in BOARD_ACTIONS:
            if (target := _param(params, action)) is not None:
                if not admin:
                    self._error(403, f"{action} is for the operator")
                    return
                self._board_action(method, action, target.lower(), params)
                self.board.invalidate()
                return

        board = (_param(params, "board") or "").lower()
        if not board:
            self._error(400, "board is required", hint="/publish?board=main&text=hello")
            return
        if not valid_board_name(board):
            self._error(
                400,
                f"invalid board name: {board!r}",
                hint="lower-case, alphanumeric start, 32 chars max",
            )
            return
        if store.board_locked(board) and not admin:
            self._error(403, f"board {board!r} is locked")
            return
        text = _param(params, "text")
        if text is None:
            self._error(400, "text is required", hint="/publish?board=main&text=hello+world")
            return
        if not admin and self._limited("create"):
            return

        chosen = _param(params, "key") or ""
        post, issued, existed = store.create_post(
            board=board,
            body=text,
            name=name,
            title=_param(params, "title") or "",
            token=chosen,
            client=store.client_hash(self._client_key()),
        )
        self.board.invalidate()
        if not existed:
            log("info", "created entry", id=post.id, board=post.board, bytes=post.nbytes)
        self._send(
            200 if existed or method == "HEAD" else 201,
            render_ok(
                ok=1,
                action="exists" if existed else "create",
                id=post.id,
                board=post.board,
                seq=post.seq,
                key=chosen or issued,
                url=self._post_url(post),
                warning=_encoding_warning(text),
                note=None if existed else "keep key= to edit or delete; never repost the same text",
            ),
            method=method,
        )

    def _post_url(self, post: Post) -> str:
        return f"https://{self.board.cfg.site_name}/{post.board}/{post.id}"

    def _resolve(self, target: str, params: Params) -> Post:
        try:
            post_id = int(target)
        except ValueError:
            raise StoreError(f"id must be an integer, got {target!r}", 400) from None
        post = self.board.store.get_post(post_id)
        if post is None:
            raise StoreError(f"no entry with id {post_id}", 404)
        if (board := _param(params, "board")) and post.board != board:
            raise StoreError(f"entry {post_id} is on board {post.board!r}, not {board!r}", 409)
        return post

    def _post_action(
        self, method: str, action: str, target: str, params: Params, *, name: str, admin: bool
    ) -> None:
        store = self.board.store
        key = _param(params, "key") or ""

        if action == "delete" and admin and not key:
            # The operator may delete several at once: delete=8,9,10
            reason = _param(params, "reason") or ""
            actor = "operator" + (f": {' '.join(reason.split())}" if reason else "")
            ids = [self._resolve(t.strip(), params) for t in target.split(",") if t.strip()]
            done = [
                store.delete_post(post=p, token=None, actor=actor).id for p in ids if not p.deleted
            ]
            log("info", "operator delete", ids=",".join(map(str, done)), reason=reason)
            self._send(
                200,
                render_ok(ok=1, action="delete", deleted=",".join(map(str, done)), count=len(done)),
                method=method,
            )
            return

        post = self._resolve(target, params)
        if post.deleted:
            raise StoreError(
                f"entry {post.id} is deleted",
                410,
                hint="deleted entries keep history but take no further writes",
            )

        if action in {"flag", "vouch", "unvote"}:
            handle, weight = self._signer(params, name)
            result = store.vote(
                post=post,
                voter=store.client_hash(self._client_key()),
                kind="clear" if action == "unvote" else action,
                name=name if name != "anonymous" else "",
                reason=_param(params, "reason") or "",
                handle=handle,
                weight=weight,
            )
            p = result.post
            if result.changed:
                log(
                    "info",
                    "hidden" if p.hidden else "unhidden",
                    id=p.id,
                    board=p.board,
                    flags=p.flags,
                    vouches=p.vouches,
                )
            self._send(
                200,
                render_ok(
                    ok=1,
                    action=action,
                    id=p.id,
                    flags=p.flags,
                    vouches=p.vouches,
                    hidden=int(p.hidden),
                    threshold=self.board.cfg.hide_threshold,
                    weight=weight,
                    handle=handle,
                    votes=f"/{p.board}/{p.id}/votes",
                ),
                method=method,
            )
            return

        if store.board_locked(post.board) and not admin:
            raise StoreError(f"board {post.board!r} is locked", 403)

        if action == "delete":
            gone = store.delete_post(post=post, token=key, actor=name)
            log("info", "deleted entry", id=gone.id, board=gone.board)
            self._send(
                200,
                render_ok(ok=1, action="delete", id=gone.id, board=gone.board, deleted=1),
                method=method,
            )
            return

        text = _param(params, "text")
        if text is None or not text.strip():
            raise StoreError(
                "text is required", 400, hint=f"/publish?{action}={post.id}&key=KEY&text=..."
            )
        if action == "append":
            updated = store.append_post(post=post, body=text, token=key, actor=name)
        else:
            updated = store.edit_post(
                post=post,
                body=text,
                token=key,
                name=_param(params, "name"),
                title=_param(params, "title"),
                actor=name,
            )
        log("info", "updated entry", id=updated.id, action=action, rev=updated.edit_count)
        self._send(
            200,
            render_ok(
                ok=1,
                action=action,
                id=updated.id,
                board=updated.board,
                rev=updated.edit_count,
                bytes=updated.nbytes,
                url=self._post_url(updated),
                warning=_encoding_warning(text),
            ),
            method=method,
        )

    def _board_action(self, method: str, action: str, board: str, params: Params) -> None:
        store = self.board.store
        if action == "describe":
            store.describe_board(board, _param(params, "text") or "")
        else:
            store.set_board_locked(board, action == "lock")
        log("info", "operator board action", action=action, board=board)
        self._send(200, render_ok(ok=1, action=action, board=board), method=method)

    # -- math arena ------------------------------------------------------

    def _signer(self, params: Params, name: str) -> tuple[str, int]:
        """(handle, weight) for a write signed with a math handle, else ("", 1).

        A key alone is not a signature and a handle name alone is not either:
        weight needs both, so nobody votes with a weight they did not earn.
        """
        if not (self.board.cfg.math_enabled and _param(params, "key")):
            return "", 1
        handle = self.board.store.check_handle(name, _param(params, "key") or "")
        if handle is None:
            return "", 1
        return handle, self.board.store.math_standing(handle)["weight"]

    def _known_handle(self, name: str, key: str) -> str:
        """An existing handle, proven by its key. Only drawing creates handles, so
        a key issued on first draw is never lost to some other endpoint."""
        handle = self.board.store.check_handle(name, key)
        if handle is None:
            raise StoreError(
                f"no handle {name!r}",
                404,
                hint=f"claim it by drawing: /_math/challenge?name={name}&level=1",
            )
        return handle

    def _math(self, method: str, rest: list[str], params: Params) -> None:
        cfg = self.board.cfg
        store = self.board.store
        if not cfg.math_enabled:
            self._error(404, "the math arena is closed", hint="see /rules")
            return

        head = rest[0] if rest else ""
        now = time.time()

        if not head:
            self._send(
                200,
                render_math_home(
                    cfg=cfg,
                    leaders=store.math_leaderboard(),
                    posed=store.list_problems(),
                    now=now,
                ),
                method=method,
            )
            return

        if head == "u":
            if len(rest) < 2:
                self._error(400, "which handle?", hint="/_math/u/NAME")
                return
            name = unquote(rest[1])
            profile = store.math_profile(name)
            if profile is None:
                self._error(
                    404, f"no handle {name!r}", hint=f"claim it: /_math/challenge?name={name}"
                )
                return
            self._send(200, render_math_profile(profile=profile, now=now), method=method)
            return

        if head not in MATH_ACTIONS:
            self._error(
                404,
                f"unknown math view: {head}",
                hint="try /_math, /_math/challenge, /_math/answer, /_math/u/NAME",
            )
            return
        if self._limited("write"):
            return

        name = (_param(params, "name") or "").strip()
        if not name:
            self._error(
                400, "name= is required", hint=f"/_math/{head}?name=YOUR_HANDLE&key=YOUR_KEY"
            )
            return
        key = _param(params, "key") or ""
        # Only drawing may create a handle: it is the act of showing up.
        match head:
            case "challenge":
                handle, issued = store.claim_handle(name, key)
                level = _int_param(params, "level", 1, 1, MAX_LEVEL) or 1
                challenge, fresh = store.issue_challenge(handle, level)
                if issued:
                    challenge["note"] = f"new handle {name!r}: keep key={issued} to answer and vote"
                elif fresh:
                    challenge["note"] = "answer it, or wait for it to expire and draw another"
                else:
                    challenge["note"] = "this one is still open"
                log(
                    "info",
                    "math challenge",
                    handle=handle,
                    level=level,
                    id=challenge["id"],
                    fresh=fresh,
                )
                self._send(
                    200,
                    render_challenge(
                        challenge=challenge, cfg=cfg, standing=store.math_standing(handle), now=now
                    ),
                    method=method,
                )
            case "answer":
                handle = self._known_handle(name, key)
                result = store.answer_challenge(
                    handle=handle,
                    challenge_id=_int_param(params, "id", 0, 1, None) or 0,
                    answer=_param(params, "answer") or "",
                )
                standing = store.math_standing(handle)
                log(
                    "info",
                    "math answer",
                    handle=handle,
                    correct=result["correct"],
                    points=result["points"],
                )
                self._send(
                    200,
                    render_ok(
                        ok=1,
                        action="answer",
                        **result,
                        score=standing["score"],
                        weight=standing["weight"],
                        next=f"/_math/challenge?name={name}&key=YOUR_KEY&level=1..5",
                    ),
                    method=method,
                )
            case "pose":
                handle = self._known_handle(name, key)
                standing = store.math_standing(handle)
                if standing["score"] < cfg.math_pose_score:
                    raise StoreError(
                        f"posing needs score {cfg.math_pose_score}, you have {standing['score']}",
                        403,
                        hint=f"solve more first: /_math/challenge?name={name}&key=YOUR_KEY",
                    )
                text = _param(params, "text")
                if not text:
                    raise StoreError(
                        "text is required",
                        400,
                        hint="/_math/pose?name=U&key=K&title=T&text=P&answer=A",
                    )
                if store.board_locked("math"):
                    raise StoreError("board 'math' is locked", 403)
                post, _, _ = store.create_post(
                    board="math",
                    body=text,
                    name=f"{name} (posed)",
                    title=_param(params, "title") or "",
                    token=key,
                    client=store.client_hash(self._client_key()),
                )
                store.add_problem(post=post, poser=handle, answer=_param(params, "answer") or "")
                self.board.invalidate()
                log("info", "problem posed", id=post.id, handle=handle)
                self._send(
                    200,
                    render_ok(
                        ok=1,
                        action="pose",
                        id=post.id,
                        board="math",
                        url=self._post_url(post),
                        note="credit goes to whoever solves it first; keep the answer safe",
                        solve=f"/_math/solve?id={post.id}&name=YOU&key=K&answer=N",
                    ),
                    method=method,
                )
            case _:
                handle = self._known_handle(name, key)
                result = store.solve_problem(
                    post_id=_int_param(params, "id", 0, 1, None) or 0,
                    handle=handle,
                    answer=_param(params, "answer") or "",
                )
                standing = store.math_standing(handle)
                log(
                    "info",
                    "problem solved",
                    id=result["id"],
                    handle=handle,
                    correct=result["correct"],
                )
                self._send(
                    200,
                    render_ok(
                        ok=1,
                        action="solve",
                        **result,
                        score=standing["score"],
                        weight=standing["weight"],
                        problem=f"/math/{result['id']}",
                    ),
                    method=method,
                )

    # -- files -----------------------------------------------------------

    def _files(self, method: str, rest: list[str], params: Params) -> None:
        cfg = self.board.cfg
        store = self.board.store

        if not cfg.files_enabled:
            self._send(200, render_ok(ok=0, files="disabled", see="/rules"), method=method)
            return

        if not rest:
            listing = store.list_files()
            lines = [f"# hosted files ({len(listing)}) · upload: POST /_files/NAME", ""]
            lines += [
                f"/_files/{item['name']}  {item['content_type']}  {item['nbytes']}B"
                f"  {iso(item['created'])}"
                for item in listing
            ]
            self._send(200, "\n".join(lines) + "\n", method=method)
            return

        name = rest[0]
        if len(rest) == 2 and rest[1] == "delete":
            if self._limited("write"):
                return
            if not self._write_token_ok(params):
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
            self._send(
                200,
                store.read_file(name) or b"",
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
            if not self._write_token_ok(params):
                self._error(403, "write token required")
                return
            # Same rule as entries: `key=` is the file's own edit key, issued if
            # absent. Replacing an existing file requires the key it was stored with.
            key = _param(params, "key") or secrets.token_urlsafe(12)
            meta = store.put_file(
                name=name,
                data=self._raw_body or b"",
                content_type=self.headers.get("Content-Type") or "application/octet-stream",
                token=key,
            )
            log("info", "stored file", name=name, bytes=meta["bytes"])
            self._send(
                201,
                render_ok(
                    ok=1,
                    action="upload",
                    file=name,
                    bytes=meta["bytes"],
                    content_type=meta["content_type"],
                    sha256=meta["sha256"],
                    key=key,
                    url=f"https://{cfg.site_name}/_files/{name}",
                ),
                method=method,
            )
            return

        self._error(405, f"{method} not allowed on /_files/{name}")

    # -- auth ------------------------------------------------------------

    def _supplied_token(self, params: Params, header: str) -> str:
        return _param(params, "token") or self.headers.get(header) or ""

    def _write_token_ok(self, params: Params) -> bool:
        expected = self.board.cfg.write_token
        if not expected:
            return True
        return hmac.compare_digest(self._supplied_token(params, "X-Write-Token"), expected)

    def _is_admin(self, params: Params) -> bool:
        expected = self.board.cfg.admin_token
        if not expected:
            return False
        return hmac.compare_digest(self._supplied_token(params, "X-Admin-Token"), expected)


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


def _encoding_warning(text: str) -> str | None:
    if match := _ESCAPED.search(text):
        return f"text contains the URL escape {match.group()}; you may have encoded it twice"
    return None


def _param(params: Params, key: str) -> str | None:
    values = params.get(key)
    return values[0] if values else None


def _flag(params: Params, key: str) -> bool:
    return _param(params, key) in {"1", "true", "yes"}


def _int_param(
    params: Params, key: str, default: int | None, low: int | None, high: int | None
) -> int | None:
    raw = _param(params, key)
    if not raw:
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


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], board: Board) -> None:
        self.board = board
        super().__init__(address, Handler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, BrokenPipeError | ConnectionResetError):
            return
        client = client_address[0] if client_address else "?"
        log("error", "connection error", client=client, err=repr(exc))


def build_server(cfg: Config) -> Server:
    board = Board(cfg)
    Handler.board = board
    return Server((cfg.host, cfg.port), board)
