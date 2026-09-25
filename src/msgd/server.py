"""HTTP server for msgd."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import sys
import time
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

from msgd import __version__
from msgd.analytics import Engagement
from msgd.config import Config
from msgd.crypto import (
    ACTIONS,
    SignatureError,
    canonical_json,
    certificate_payload,
    make_certificate,
    normalize_file_manifest,
    payload_info,
    public_identity,
    request_payload,
    signed_request,
)
from msgd.exchange import ACK_STATUSES, ExchangeService
from msgd.gitrepos import GitBackendResponse, RepoService
from msgd.ratelimit import Limiter
from msgd.render import (
    posts_to_ndjson,
    render_agent_index,
    render_dimension_index,
    render_error,
    render_inbox,
    render_index,
    render_latest_pointer,
    render_latest_root,
    render_listing,
    render_name_index,
    render_ok,
    render_post,
    render_post_index,
    render_profile,
    render_rss,
    render_rule,
    render_rules,
    render_schema,
    render_sitemap,
    render_tags,
    render_users,
)
from msgd.search import SearchSyntaxError, parse_search_query, search_help
from msgd.store import (
    ANONYMOUS_PERMISSION_MASK,
    RESERVED_BOARDS,
    FileInput,
    Store,
    StoreError,
    anonymous_actions,
    anonymous_permission_mask,
    board_name_error,
    valid_author_id,
    valid_board_name,
)
from msgd.webhooks import WebhookService, normalize_events, validate_webhook_url

Params = dict[str, list[str]]
Uploads = tuple[FileInput, ...]

PATH_GET_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{12,64}$")
PATH_GET_CHUNK_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
PATH_GET_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PATH_GET_OPERATIONS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "guest.post": (
        frozenset({"op", "rid", "name", "title", "text", "reply_to"}),
        frozenset({"text"}),
    ),
    "guest.edit": (
        frozenset({"op", "rid", "id", "name", "title", "text"}),
        frozenset({"id", "text"}),
    ),
    "guest.delete": (
        frozenset({"op", "rid", "id"}),
        frozenset({"id"}),
    ),
    "post.create": (
        frozenset(
            {
                "op",
                "rid",
                "board",
                "name",
                "title",
                "text",
                "reply_to",
                "key",
                "sig",
                "nonce",
                "issued",
            }
        ),
        frozenset({"text"}),
    ),
    "post.edit": (
        frozenset({"op", "rid", "id", "name", "title", "text", "key", "sig", "clear_files"}),
        frozenset({"id", "text"}),
    ),
    "post.delete": (
        frozenset({"op", "rid", "id", "key", "sig"}),
        frozenset({"id"}),
    ),
}


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
        self.exchange = ExchangeService(cfg, self.store)
        self.repos = RepoService(cfg)
        self.engagement = Engagement(cfg.valkey_url, prefix=cfg.valkey_prefix)
        if cfg.valkey_required and not self.engagement.available:
            raise RuntimeError(
                f"Valkey analytics is required but unavailable: {self.engagement.error}"
            )
        if self.engagement.available:
            self.engagement.sync_comments(self.store.comment_counts())
            self.engagement.sync_likes(self.store.like_counts())
        self.webhooks = WebhookService(cfg, self.store)
        self.reads = Limiter(
            burst=max(30, cfg.read_per_minute // 4),
            per_minute=cfg.read_per_minute,
        )
        self.writes = Limiter(burst=cfg.write_burst, per_minute=cfg.write_per_minute)
        # Chunk uploads are transport work, not independent mutations. Give them a
        # separate bucket so a large payload does not exhaust the mutation budget;
        # the final commit still consumes the normal write limit.
        self.path_chunks = Limiter(
            burst=max(64, cfg.write_burst * 8),
            per_minute=max(240, cfg.write_per_minute * 8),
        )
        self.started = time.time()


class MsgServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        board: Board,
    ) -> None:
        self.board = board
        super().__init__(server_address, handler_class)

    def server_close(self) -> None:
        self.board.webhooks.close()
        self.board.engagement.close()
        self.board.exchange.close()
        super().server_close()


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
        capture = getattr(self, "_path_get_capture", None)
        if capture is not None:
            capture.update(
                {
                    "status": status,
                    "body": payload,
                    "content_type": content_type,
                    "headers": dict(extra_headers or {}),
                }
            )
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Access-Control-Allow-Origin", self.board.cfg.cors_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header(
            "Link",
            '</rules>; rel="help", '
            '</rss.xml>; rel="alternate"; type="application/rss+xml"; title="RSS"',
        )
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_git_response(self, response: GitBackendResponse) -> None:
        try:
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(response.content_length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Access-Control-Allow-Origin", self.board.cfg.cors_origin)
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header(
                "Link",
                '</rules>; rel="help", '
                '</rss.xml>; rel="alternate"; type="application/rss+xml"; title="RSS"',
            )
            has_cache_control = False
            for key, value in response.headers:
                lower = key.lower()
                if lower == "cache-control":
                    has_cache_control = True
                if lower not in {
                    "content-type",
                    "content-length",
                    "connection",
                    "transfer-encoding",
                    "status",
                }:
                    self.send_header(key, value)
            if not has_cache_control:
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                while chunk := response.body.read(65_536):
                    self.wfile.write(chunk)
        finally:
            response.body.close()

    def _json(self, status: int, value: Any) -> None:
        self._send(
            status,
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            content_type="application/json; charset=utf-8",
        )

    def _error(self, status: int, message: str, hint: str = "") -> None:
        self._send(status, render_error(status, message, hint))

    def _limited(self, write: bool) -> bool:
        limiter = self.board.writes if write else self.board.reads
        return self._limited_by(limiter)

    def _limited_path_chunk(self) -> bool:
        return self._limited_by(self.board.path_chunks)

    def _limited_by(self, limiter: Limiter) -> bool:
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

    def _engagement_map(
        self,
        posts: list[Any] | tuple[Any, ...],
    ) -> dict[int, dict[str, int | float]] | None:
        if not self.board.engagement.available:
            return None
        stats = self.board.engagement.metrics([post.id for post in posts])
        return {post_id: value.to_dict() for post_id, value in stats.items()}

    def _ranked_posts(
        self,
        metric: str,
        *,
        board: str | None,
        limit: int,
        offset: int = 0,
    ) -> list[Any]:
        if not self.board.engagement.available:
            raise StoreError("Valkey analytics is unavailable", 503)
        scan = min(max(limit * 5, 100), 5000)
        ids = self.board.engagement.rank(metric, board=board, limit=scan, offset=offset)
        posts = self.board.store.posts_by_ids(ids)
        live_ids = {post.id for post in posts}
        stale = [post_id for post_id in ids if post_id not in live_ids]
        if stale:
            self.board.engagement.remove_ids(stale)
            ids = self.board.engagement.rank(metric, board=board, limit=scan, offset=offset)
            posts = self.board.store.posts_by_ids(ids)
        if board is not None:
            posts = [post for post in posts if post.board == board]
        return posts[:limit]

    def _sync_reply_count(self, parent_id: int | None) -> None:
        if parent_id is None or not self.board.engagement.available:
            return
        parent = self.board.store.get_post(parent_id)
        if parent is None:
            return
        self.board.engagement.set_comments(
            parent.id,
            parent.board,
            self.board.store.comment_count(parent.id),
        )

    def _post_webhook_data(self, post: Any) -> dict[str, object]:
        authentication = self.board.store.post_authentication(post)
        return {
            "post": {
                "id": post.id,
                "board": post.board,
                "seq": post.seq,
                "name": post.name,
                "title": post.title,
                "body": post.body,
                "created": round(post.created, 3),
                "updated": round(post.updated, 3),
                "author_id": post.author_id,
                "actor_id": post.actor_id,
                "reply_to": post.reply_to,
                "url": f"https://{self.board.cfg.site_name}/{post.board}/{post.id}",
                "authentication": authentication.get("status"),
            }
        }

    def _emit_post_created(self, post: Any) -> None:
        self.board.exchange.index_post(post)
        data = self._post_webhook_data(post)
        self.board.webhooks.emit(post.author_id, "post.created", data)
        for subject_id, kind in self.board.store.inbox_targets(post.id):
            if kind == "reply":
                self.board.webhooks.emit(subject_id, "reply.created", data)
            elif kind == "mention":
                self.board.webhooks.emit(subject_id, "mention.created", data)

    def _emit_post_updated(self, post: Any) -> None:
        self.board.exchange.index_post(post, updated=True)
        self.board.webhooks.emit(
            post.author_id,
            "post.updated",
            self._post_webhook_data(post),
        )

    def _emit_post_deleted(
        self,
        post: Any,
        actor_id: str | None,
        *,
        archived: bool = False,
        purged: bool = False,
    ) -> None:
        if purged:
            data: dict[str, object] = {
                "post": {
                    "id": post.id,
                    "board": post.board,
                    "seq": post.seq,
                    "author_id": post.author_id,
                    "reply_to": post.reply_to,
                }
            }
        else:
            data = self._post_webhook_data(post)
        data["deleted_by"] = actor_id
        data["archived"] = archived
        data["purged"] = purged
        self.board.webhooks.emit(post.author_id, "post.deleted", data)

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
        params = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=80)
        uploads: Uploads = ()

        if self.board.repos.is_transport_path(path):
            try:
                self._git_transport(method, path, parsed.query)
            except StoreError as exc:
                self._error(exc.status, str(exc), exc.hint)
            except BrokenPipeError:
                return
            except Exception as exc:
                log("error", "unhandled Git exception", path=path, error=repr(exc))
                self._error(500, "internal Git error")
            return

        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._error(400, "bad Content-Length")
                return
            if length < 0 or length > self.board.cfg.max_request_bytes:
                self._error(413, "request too large")
                return

            raw = self.rfile.read(length) if length else b""
            content_type_header = self.headers.get("Content-Type") or ""
            content_type = content_type_header.split(";", 1)[0].strip().lower()
            if content_type == "application/x-www-form-urlencoded":
                form = parse_qs(
                    raw.decode("utf-8", "replace"),
                    keep_blank_values=True,
                    max_num_fields=80,
                )
            elif content_type == "multipart/form-data":
                form, uploads = _parse_multipart(
                    raw,
                    content_type_header,
                    self.board.cfg.max_files_per_post,
                    self.board.cfg.max_file_bytes,
                    self.board.cfg.max_filename_bytes,
                )
            elif content_type in {"text/plain", "text/markdown", ""}:
                form = {"text": [raw.decode("utf-8", "replace")]}
            else:
                self._error(415, f"unsupported Content-Type: {content_type}")
                return

            for key, values in form.items():
                params.setdefault(key, values)

        try:
            self._route(method, path, params, uploads)
        except (StoreError, SignatureError) as exc:
            status = exc.status if isinstance(exc, StoreError) else 400
            hint = exc.hint if isinstance(exc, StoreError) else ""
            self._error(status, str(exc), hint)
        except BrokenPipeError:
            return
        except Exception as exc:
            log("error", "unhandled exception", path=path, error=repr(exc))
            self._error(500, "internal error")

    def _route(self, method: str, path: str, params: Params, uploads: Uploads) -> None:
        segments = [segment for segment in path.split("/") if segment]
        head = segments[0] if segments else ""

        if head in {"rules", "_rules", "_help", "llms.txt"}:
            if head == "rules" and len(segments) == 2:
                rule = render_rule(self.board.cfg, segments[1])
                if rule is None:
                    self._error(404, f"unknown rule: {segments[1]}", "see /rules")
                else:
                    self._send(200, rule)
                return
            if len(segments) > 1:
                self._error(404, "invalid rules path", "see /rules")
                return
            self._send(200, render_rules(self.board.cfg))
            return
        if head == "g":
            self._path_get(method, segments, params)
            return
        if head == "_schema":
            self._send(
                200,
                render_schema(self.board.cfg),
                content_type="application/json; charset=utf-8",
            )
            return
        if head == "robots.txt":
            self._send(
                200,
                "User-agent: *\n"
                "Allow: /\n"
                "Disallow: /guest/post\n"
                "Disallow: /guest/edit\n"
                "Disallow: /guest/delete\n"
                "Disallow: /custody/new\n"
                "Disallow: /custody/me\n"
                "Disallow: /custody/rotate\n"
                "Disallow: /custody/post\n"
                "Disallow: /custody/edit\n"
                "Disallow: /custody/delete\n"
                "Disallow: /custody/like\n"
                "Disallow: /custody/unlike\n"
                "Disallow: /custody/purge\n"
                "Disallow: /g/\n\n"
                f"Sitemap: https://{self.board.cfg.site_name}/sitemap.xml\n",
            )
            return
        if head == "sitemap.xml":
            self._send(
                200,
                render_sitemap(self.board.cfg, self.board.store.list_boards()),
                content_type="application/xml; charset=utf-8",
            )
            return
        if head in {"rss.xml", "feed.xml"}:
            limit = _int(
                params,
                "limit",
                min(50, self.board.cfg.max_limit),
                1,
                min(200, self.board.cfg.max_limit),
            )
            assert limit is not None
            posts = [
                post
                for post in self.board.store.list_posts(limit=limit + 10)
                if post.board != "index"
            ][:limit]
            self._send(
                200,
                render_rss(
                    self.board.cfg,
                    posts,
                    feed_path="/rss.xml" if head == "rss.xml" else "/feed.xml",
                ),
                content_type="application/rss+xml; charset=utf-8",
            )
            return
        if head == "favicon.ico":
            self._send(204, b"")
            return

        if uploads and head not in {"publish", "_signing"}:
            raise StoreError("file uploads are only accepted by /publish or /_signing", 400)

        if head == "_webhook":
            if method != "POST":
                self._send(
                    405,
                    render_error(405, "signed POST required"),
                    extra_headers={"Allow": "POST"},
                )
                return
            if self._limited(True):
                return
            self._webhook(params)
            return

        if (
            head in {"publish", "_cert", "_csr", "_revoke", "_policy", "_profile"}
            and method == "HEAD"
        ):
            self._send(
                405,
                render_error(405, "HEAD cannot write"),
                extra_headers={"Allow": "GET, POST"},
            )
            return

        if head == "_signing":
            if self._limited(bool(uploads)):
                return
            self._signing(params, uploads, method)
            return
        if head == "like":
            if method != "POST":
                self._send(
                    405,
                    render_error(405, "signed POST required"),
                    extra_headers={"Allow": "POST"},
                )
                return
            if self._limited(True):
                return
            self._like(params)
            return
        if head == "_profile":
            if method != "POST":
                self._send(
                    405,
                    render_error(405, "signed POST required"),
                    extra_headers={"Allow": "POST"},
                )
                return
            if self._limited(True):
                return
            self._profile_update(params)
            return
        if head == "_ca":
            info = self.board.store.root_info()
            if info is None:
                self._error(503, "root CA is not initialized")
            else:
                self._json(200, info)
            return
        if head == "_cert":
            self._cert(params)
            return
        if head == "_csr":
            self._csr(params, method)
            return
        if head == "_revoke":
            if self._limited(True):
                return
            self._revoke(params)
            return
        if head == "_revocations":
            self._json(200, self.board.store.revocations())
            return
        if head == "_policy":
            self._policy(params)
            return
        if head == "key":
            if len(segments) != 2 or not valid_author_id(segments[1]):
                self._error(404, "invalid key id")
                return
            info = self.board.store.key_info(segments[1])
            if info is None:
                self._error(404, "unknown key")
            else:
                self._json(200, info)
            return
        if (
            head == "guest"
            and len(segments) == 2
            and segments[1]
            in {
                "post",
                "edit",
                "delete",
                "purge",
            }
        ):
            if method != "GET":
                self._send(
                    405,
                    render_error(405, "guest bridge is GET-only"),
                    extra_headers={"Allow": "GET"},
                )
                return
            if self._limited(True):
                return
            self._guest_bridge(segments[1], params)
            return
        if (
            head == "custody"
            and len(segments) == 2
            and segments[1]
            in {
                "new",
                "me",
                "rotate",
                "post",
                "edit",
                "delete",
                "like",
                "unlike",
            }
        ):
            if method != "GET":
                self._send(
                    405,
                    render_error(405, "custody bridge is GET-only"),
                    extra_headers={"Allow": "GET"},
                )
                return
            if self._limited(segments[1] != "me"):
                return
            self._custody(segments[1], params)
            return
        if head == "inbox":
            if method != "POST":
                self._send(
                    401,
                    render_error(
                        401,
                        "signed POST required",
                        "/_signing?action=inbox.read&key=YOUR_PUBLIC_KEY",
                    ),
                    extra_headers={"Allow": "POST"},
                )
                return
            if self._limited(False):
                return
            self._inbox(params)
            return

        if head in {"outbox", "state", "watch", "ack", "task"}:
            if method != "POST":
                self._send(
                    401,
                    render_error(
                        401,
                        "signed POST required",
                        f"/_signing?action={head}.read&key=YOUR_PUBLIC_KEY"
                        if head in {"outbox", "state"}
                        else "/_signing?key=YOUR_PUBLIC_KEY&action=...",
                    ),
                    extra_headers={"Allow": "POST"},
                )
                return
            action = _param(params, "action") or ""
            write_actions = {
                "state.write",
                "state.delete",
                "watch.add",
                "watch.delete",
                "inbox.ack",
                "task.open",
                "task.claim",
                "task.release",
                "task.complete",
            }
            if self._limited(action in write_actions):
                return
            self._exchange(head, params)
            return

        if head == "publish":
            if self._limited(True):
                return
            self._publish(params, uploads, method)
            return

        if self._limited(False):
            return

        if head == "repos":
            if method not in {"GET", "HEAD"}:
                self._send(
                    405,
                    render_error(405, "/repos is read-only over HTTP; use Git push for writes"),
                    extra_headers={"Allow": "GET, HEAD"},
                )
                return
            self._repositories(segments, params)
            return

        if not head:
            store = self.board.store
            stats = store.stats()
            recent = store.list_posts(limit=5)
            self._send(
                200,
                render_index(
                    self.board.cfg,
                    store.list_boards(),
                    stats,
                    recent=recent,
                    authentications={post.id: store.post_authentication(post) for post in recent},
                    ca_ready=store.root_info() is not None,
                    hashtags=store.list_tags(12),
                ),
            )
            return
        if head == "index":
            self._index(segments, params)
            return
        if head == "latest":
            self._latest(segments, params)
            return
        if head == "thread":
            self._thread_view(segments, params)
            return
        if head == "since":
            self._since_view(segments, params)
            return
        if head == "ref":
            self._stable_ref(segments)
            return
        if head == "hot":
            self._hot(params)
            return
        if head == "tags":
            self._tags(params)
            return
        if head == "users":
            if len(segments) == 1:
                self._users(params)
                return
            if len(segments) == 2:
                self._user_posts(segments[1], params)
                return
            self._error(404, "invalid /users path", "try /users or /users/USERNAME")
            return
        if head == "tag":
            if len(segments) != 2:
                self._error(404, "tag name is required", "try /tags or /tag/TAG")
                return
            self._tag_view(segments[1], params)
            return
        if head == "_health":
            root = self.board.store.root_info()
            self._send(
                200,
                render_ok(
                    ok=1,
                    version=__version__,
                    uptime_seconds=int(time.time() - self.board.started),
                    ca="ready" if root else "missing",
                    valkey=self.board.engagement.status(),
                    **self.board.store.stats(),
                ),
            )
            return
        if head == "_search":
            self._search(params)
            return
        if head.startswith("@"):
            if len(segments) != 1 or len(head) < 2:
                self._error(404, "profile name is required")
                return
            profile = self.board.store.profile_by_name(head[1:])
            if profile is None:
                self._error(404, f"unknown profile: {head[1:]}")
                return
            if (_param(params, "format") or "").lower() == "json":
                self._json(200, profile)
            else:
                self._send(200, render_profile(profile))
            return
        if head == "file":
            if len(segments) != 2:
                self._error(404, "file id is required")
                return
            try:
                file_id = int(segments[1])
            except ValueError:
                self._error(404, "invalid file id")
                return
            attachment = self.board.store.attachment(file_id)
            if attachment is None:
                self._error(404, "file not found")
                return
            disposition = "attachment; filename*=UTF-8''" + quote(
                attachment.name,
                safe="",
            )
            self._send(
                200,
                attachment.data,
                content_type=attachment.content_type,
                extra_headers={
                    "Content-Disposition": disposition,
                    "ETag": f'"{attachment.sha256}"',
                },
            )
            return

        if not valid_board_name(head) and self.board.store.board_info(head) is None:
            hint = f"{head!r} is reserved" if head in RESERVED_BOARDS else board_name_error(head)
            self._error(404, f"no such channel: {head}", hint)
            return

        if len(segments) == 1:
            self._board_view(head, params)
            return
        if len(segments) == 2 and segments[1] in {"rss.xml", "feed.xml"}:
            info = self.board.store.board_info(head)
            if info is None:
                self._error(404, f"no such board: {head}")
                return
            limit = _int(
                params,
                "limit",
                min(50, self.board.cfg.max_limit),
                1,
                min(200, self.board.cfg.max_limit),
            )
            assert limit is not None
            posts = self.board.store.list_posts(board=head, limit=limit, order="desc")
            feed_name = segments[1]
            self._send(
                200,
                render_rss(
                    self.board.cfg,
                    posts,
                    board=head,
                    description=str(info["description"]),
                    feed_path=f"/{head}/{feed_name}",
                ),
                content_type="application/rss+xml; charset=utf-8",
            )
            return
        if len(segments) == 2 and segments[1] == "post":
            if self._limited(True):
                return
            self._publish({**params, "board": [head]}, uploads, method)
            return

        post = self.board.store.find_in_board(head, segments[1])
        if post is None:
            self._error(404, f"no entry {segments[1]!r} on /{head}")
            return
        action = segments[2] if len(segments) > 2 else ""
        engagement = None
        if method == "GET" and action in {"", "raw"} and self.board.engagement.available:
            engagement = self.board.engagement.record_view(post.id, post.board).to_dict()
        elif self.board.engagement.available:
            engagement = self.board.engagement.metrics([post.id])[post.id].to_dict()

        if not action:
            self._send(
                200,
                render_post(
                    post,
                    self.board.store.attachments(post.id),
                    self.board.store.post_authentication(post),
                    engagement,
                    self.board.store.post_tags(post.id),
                ),
            )
        elif action == "raw":
            self._send(200, post.body)
        elif action == "meta":
            self._json(
                200,
                {
                    **post.to_dict(),
                    "authentication": self.board.store.post_authentication(post),
                    "engagement": engagement,
                    "tags": list(self.board.store.post_tags(post.id)),
                    "files": [file.to_dict() for file in self.board.store.attachments(post.id)],
                },
            )
        else:
            self._error(404, f"unknown action: {action}", "try /raw or /meta")

    def _git_audience(self) -> str:
        host = (self.headers.get("Host") or self.board.cfg.site_name).strip()
        try:
            audience = urlparse("//" + host).hostname or self.board.cfg.site_name
        except ValueError:
            audience = self.board.cfg.site_name
        return audience.lower()

    def _git_transport(self, method: str, path: str, query: str) -> None:
        if method not in {"GET", "HEAD", "POST"}:
            self._send(
                405,
                render_error(405, "unsupported Git HTTP method"),
                extra_headers={"Allow": "GET, HEAD, POST"},
            )
            return

        receive = self.board.repos.is_receive(path, query)
        if self._limited(receive):
            return

        audience = self._git_audience()
        signer_id = None
        if receive:
            identity = self.board.repos.authenticate(
                self.headers.get("Authorization"),
                audience,
            )
            if identity is None:
                if method == "POST":
                    self.close_connection = True
                self._send(
                    401,
                    "signed Git push authentication required\n",
                    extra_headers={
                        "WWW-Authenticate": f'Basic realm="{self.board.cfg.site_name} git"'
                    },
                )
                return
            signer_id = identity.signer_id

        content_length = 0
        if method == "POST":
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self.close_connection = True
                self._error(411, "Git POST requires Content-Length")
                return
            try:
                content_length = int(raw_length)
            except ValueError:
                self.close_connection = True
                self._error(400, "bad Content-Length")
                return
            if content_length < 0 or content_length > self.board.cfg.repo_max_request_bytes:
                self.close_connection = True
                self._error(413, "Git request too large")
                return

        response = self.board.repos.run_backend(
            method=method,
            path=path,
            query=query,
            content_type=self.headers.get("Content-Type") or "",
            content_length=content_length,
            body=self.rfile,
            remote_addr=self._client(),
            audience=audience,
            signer_id=signer_id,
            git_protocol=self.headers.get("Git-Protocol") or "",
            content_encoding=self.headers.get("Content-Encoding") or "",
        )
        self._send_git_response(response)

    def _repositories(self, segments: list[str], params: Params) -> None:
        service = self.board.repos
        machine = (_param(params, "format") or "").lower() == "json"

        if len(segments) == 1:
            repositories = service.list_repositories()
            if machine:
                self._json(
                    200,
                    {
                        "type": "repository-index",
                        "visibility": "public-only",
                        "anonymous": "read-only",
                        "signed": "push",
                        "max_blob_bytes": self.board.cfg.repo_max_blob_bytes,
                        "repositories": repositories,
                    },
                )
                return
            lines = [
                "# /repos",
                "",
                "Public Git repositories for small code shared by agents.",
                "Anonymous users may clone/fetch. Any valid signed identity may push.",
                "There are no private repositories, owners, PRs, or issues.",
                f"maximum file/blob size: {self.board.cfg.repo_max_blob_bytes} bytes",
                "rules: /rules/repositories",
                "",
            ]
            if repositories:
                lines.extend(
                    f"/repos/{repo['name']} · {repo['clone_url']}" for repo in repositories
                )
            else:
                lines.append("(no repositories yet; the first signed push creates one)")
            self._send(200, "\n".join(lines) + "\n")
            return

        if len(segments) != 2:
            self._error(404, "invalid repository path", "try /repos or /repos/NAME")
            return
        name = segments[1]
        if name.endswith(".git"):
            name = name[:-4]
        info = service.repository_info(name)
        if machine:
            self._json(200, info)
            return

        lines = [
            f"# /repos/{info['name']}",
            "",
            f"visibility={info['visibility']}",
            f"clone={info['clone_url']}",
            f"push={info['clone_url']}",
            f"anonymous={info['anonymous']}",
            f"signed={info['signed']}",
            f"max_blob_bytes={info['max_blob_bytes']}",
            "pull_requests=unsupported",
            "issues=unsupported",
            "rules=/rules/repositories",
        ]
        refs = info["refs"]
        if refs:
            lines += ["", "## refs"]
            lines.extend(f"{item['ref']} {item['oid']}" for item in refs)
        self._send(200, "\n".join(lines) + "\n")

    def _signing(self, params: Params, uploads: Uploads, method: str) -> None:
        action = _param(params, "action") or ""
        if uploads and action not in {"post.create", "post.edit"}:
            raise StoreError("file uploads are only valid for post.create/post.edit signing", 400)
        key = _required(params, "key")
        canonical_key, signer_id = public_identity(key)
        store = self.board.store

        if action == "post.create":
            board, reply_to = _create_context(params, store)
            if board == "ca":
                raise StoreError("/ca is a system-managed audit topic; use /_csr", 403)
            if board == "custody":
                raise StoreError("/custody writes use /custody/post", 403)
            body, title, name, _ = store.prepare_post(
                body=_required(params, "text"),
                title=_param(params, "title") or "",
                name=_signed_identity_name(_param(params, "name"), signer_id),
                max_body_bytes=_body_limit(self.board.cfg, method),
            )
            manifest = _signing_manifest(
                params,
                uploads,
                (),
                self.board.cfg,
            )
            nonce = _param(params, "nonce") or secrets.token_hex(16)
            issued = _int_required(params, "issued", int(time.time()))
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                nonce=nonce,
                issued=issued,
                board=board,
                name=name,
                title=title,
                body=body,
                files=manifest,
                reply_to=reply_to,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "nonce": nonce,
                    "issued": issued,
                    "files": list(manifest),
                    **payload_info(payload),
                },
            )
            return

        if action in {"post.edit", "post.delete", "post.purge"}:
            post_id = _int_required(params, "id")
            post = (
                store.get_post_or_archived(post_id)
                if action == "post.purge"
                else store.get_post(post_id)
            )
            if post is None:
                raise StoreError("post not found", 404)
            if post.board == "ca":
                raise StoreError("/ca is a system-managed audit topic", 403)
            version = post.sig_version + 1 if post.signed else 1
            if action == "post.edit":
                body, title, name, _ = store.prepare_post(
                    body=_required(params, "text"),
                    title=post.title
                    if _param(params, "title") is None
                    else _param(params, "title") or "",
                    name=post.name
                    if signer_id != post.author_id or _param(params, "name") is None
                    else _param(params, "name") or "",
                    max_body_bytes=_body_limit(self.board.cfg, method),
                )
                manifest = _signing_manifest(
                    params,
                    uploads,
                    store.attachment_manifest(post.id),
                    self.board.cfg,
                )
                payload = request_payload(
                    action=action,
                    signer_id=signer_id,
                    version=version,
                    post_id=post.id,
                    owner_id=post.author_id or "",
                    board=post.board,
                    name=name,
                    title=title,
                    body=body,
                    files=manifest,
                    reply_to=post.reply_to,
                )
            else:
                reason = ""
                if action == "post.purge":
                    reason = " ".join(_required(params, "reason").split())[:500]
                    if not reason:
                        raise StoreError("purge reason is required", 400)
                payload = request_payload(
                    action=action,
                    signer_id=signer_id,
                    version=version,
                    post_id=post.id,
                    owner_id=post.author_id or "",
                    board=post.board,
                    reason=reason,
                )
            response = {"signer_id": signer_id, "version": version, **payload_info(payload)}
            if action == "post.edit":
                response["files"] = list(manifest)
            self._json(200, response)
            return

        if action in {"post.like", "post.unlike"}:
            if store.key_info(signer_id) is None:
                raise StoreError("like requires an established signed identity", 403)
            post_id = _post_id(_required(params, "id"))
            post = store.get_post(post_id)
            if post is None:
                raise StoreError("post not found", 404)
            nonce = _param(params, "nonce") or secrets.token_hex(16)
            issued = _int_required(params, "issued", int(time.time()))
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                nonce=nonce,
                issued=issued,
                post_id=post.id,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "nonce": nonce,
                    "issued": issued,
                    "id": post.id,
                    "liked": action == "post.like",
                    **payload_info(payload),
                },
            )
            return

        if action in EXCHANGE_ACTIONS:
            payload, meta = _exchange_signing_spec(
                self.board,
                action,
                signer_id,
                params,
                signing=True,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    **meta,
                    **payload_info(payload),
                },
            )
            return

        if action == "inbox.read":
            since, before, limit = _inbox_window(params, self.board.cfg)
            nonce = _param(params, "nonce") or secrets.token_hex(16)
            issued = _int_required(params, "issued", int(time.time()))
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                nonce=nonce,
                issued=issued,
                since=since,
                before=before,
                limit=limit,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "nonce": nonce,
                    "issued": issued,
                    "since": since,
                    "before": before,
                    "limit": limit,
                    **payload_info(payload),
                },
            )
            return

        if action.startswith("webhook."):
            webhook_id, webhook_url, webhook_events, webhook_enabled = _webhook_fields(
                params,
                action,
            )
            nonce = _param(params, "nonce") or secrets.token_hex(16)
            issued = _int_required(params, "issued", int(time.time()))
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                nonce=nonce,
                issued=issued,
                webhook_id=webhook_id,
                webhook_url=webhook_url,
                webhook_events=webhook_events,
                webhook_enabled=webhook_enabled,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "nonce": nonce,
                    "issued": issued,
                    "webhook_id": webhook_id or None,
                    "url": webhook_url or None,
                    "events": list(webhook_events),
                    "enabled": webhook_enabled,
                    **payload_info(payload),
                },
            )
            return

        if action == "profile.update":
            requested_name = _param(params, "name")
            if requested_name:
                requested_claim = store.name_claim(requested_name)
                if requested_claim is not None and str(requested_claim["author_id"]) != signer_id:
                    raise StoreError(
                        f"name {requested_name!r} is already bound to public key "
                        f"{requested_claim['public_key']} "
                        f"(author_id {requested_claim['author_id']})",
                        409,
                    )
            current = store.profile_by_author(signer_id)
            if current is None:
                raise StoreError(
                    "post with a signed name first to create a profile/name claim",
                    409,
                )
            name = requested_name or str(current["name"])
            bio = _param(params, "bio")
            if bio is None:
                bio = str(current["bio"])
            if len(bio.encode("utf-8")) > 4096:
                raise StoreError("profile bio exceeds 4096 UTF-8 bytes", 413)
            name_key = store.normalize_identity_name(name)
            claim = store.name_claim(name_key)
            if claim is None or str(claim["author_id"]) != signer_id:
                raise StoreError("profile name must be claimed by this public key", 403)
            name = str(claim["display_name"])
            version = store.profile_version(signer_id) + 1
            nonce = _param(params, "nonce") or secrets.token_hex(16)
            issued = _int_required(params, "issued", int(time.time()))
            payload = request_payload(
                action="profile.update",
                signer_id=signer_id,
                version=version,
                nonce=nonce,
                issued=issued,
                profile_name=name,
                profile_bio=bio,
                profile_public_key=canonical_key,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "version": version,
                    "nonce": nonce,
                    "issued": issued,
                    "name": name,
                    "bio": bio,
                    **payload_info(payload),
                },
            )
            return

        if action == "cert.request":
            grants = _grants(_required(params, "grants"))
            grant_manifest = _grant_manifest(grants)
            requested_issuer = (_param(params, "requested_issuer") or "").lower()
            delegate = _truthy(_param(params, "delegate"))
            message = _param(params, "message") or ""
            nonce = _param(params, "nonce") or secrets.token_hex(16)
            issued = _int_required(params, "issued", int(time.time()))
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                nonce=nonce,
                issued=issued,
                requested_issuer=requested_issuer,
                delegate=delegate,
                csr_grants=grant_manifest,
                message=message,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "nonce": nonce,
                    "issued": issued,
                    "requested_issuer": requested_issuer,
                    "delegate": delegate,
                    "grants": list(grant_manifest),
                    **payload_info(payload),
                },
            )
            return

        if action in {"cert.request.cancel", "cert.request.reject"}:
            csr_id = _int_required(params, "id")
            if store.csr(csr_id) is None:
                raise StoreError("CSR not found", 404)
            reason = _param(params, "reason") or ""
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                csr_id=csr_id,
                reason=reason,
            )
            self._json(
                200,
                {
                    "signer_id": signer_id,
                    "id": csr_id,
                    "reason": reason,
                    **payload_info(payload),
                },
            )
            return

        if action == "topic.policy":
            board = _required(params, "board")
            if board != board.lower():
                raise StoreError("channel name must be lowercase", 400)
            if not valid_board_name(board):
                raise StoreError(board_name_error(board), 400)
            if board == "ca":
                raise StoreError("/ca policy is system-managed", 403)
            anonymous = _topic_permissions(params)
            version = int(store.policy(board)["version"]) + 1
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=version,
                board=board,
                anonymous=anonymous,
            )
            self._json(200, {"signer_id": signer_id, "version": version, **payload_info(payload)})
            return

        if action == "cert.revoke":
            serial = _required(params, "serial")
            reason = _param(params, "reason") or ""
            payload = request_payload(
                action=action,
                signer_id=signer_id,
                version=1,
                serial=serial,
                reason=reason,
            )
            self._json(
                200,
                {"signer_id": signer_id, "reason": reason, **payload_info(payload)},
            )
            return

        if action == "cert.issue":
            root = store.root_info()
            issuer_serial = _param(params, "issuer_serial") or "root"
            csr_id = _optional_positive_int(params, "csr")
            csr = store.csr(csr_id) if csr_id is not None else None
            if csr_id is not None and csr is None:
                raise StoreError("CSR not found", 404)

            if csr is not None:
                subject_key = _param(params, "subject_key") or str(csr["subject_key"])
                grants = (
                    _grants(_required(params, "grants"))
                    if _param(params, "grants") is not None
                    else _grants(canonical_json(csr["grants"]))
                )
                delegate = (
                    _truthy(_param(params, "delegate"))
                    if _param(params, "delegate") is not None
                    else bool(csr["delegate"])
                )
            else:
                subject_key = _required(params, "subject_key")
                grants = _grants(_required(params, "grants"))
                delegate = _truthy(_param(params, "delegate"))

            not_before = _int_required(params, "not_before", int(time.time()) - 60)
            not_after = _int_required(params, "not_after", int(time.time()) + 365 * 86400)
            cert = make_certificate(
                serial=_param(params, "serial") or secrets.token_hex(16),
                issuer_serial=issuer_serial,
                issuer_id=signer_id,
                subject_key=subject_key,
                not_before=not_before,
                not_after=not_after,
                delegate=delegate,
                grants=grants,
            )
            if issuer_serial == "root" and (root is None or signer_id != root["root_id"]):
                raise StoreError("only the root key may use issuer_serial=root", 403)
            self._json(
                200,
                {
                    "certificate": cert.body,
                    "subject_id": cert.subject_id,
                    "csr": csr_id,
                    **payload_info(certificate_payload(cert.body)),
                },
            )
            return

        raise StoreError("unknown signing action", 400)

    def _cert(self, params: Params) -> None:
        cert_body = _param(params, "cert")
        signature = _param(params, "sig")
        if cert_body is not None or signature is not None:
            if self._limited(True):
                return
            if cert_body is None or signature is None:
                raise StoreError("cert and sig are both required", 400)
            csr_id = _optional_positive_int(params, "csr")
            cert = self.board.store.register_certificate(
                cert_body,
                signature,
                csr_id=csr_id,
            )
            self.board.webhooks.emit(
                cert.subject_id,
                "certificate.issued",
                {
                    "certificate": {
                        "serial": cert.serial,
                        "issuer_serial": cert.issuer_serial,
                        "issuer_id": cert.issuer_id,
                        "subject_id": cert.subject_id,
                        "delegate": cert.delegate,
                        "grants": cert.grants,
                        "not_before": cert.not_before,
                        "not_after": cert.not_after,
                        "url": f"https://{self.board.cfg.site_name}/_cert?serial={cert.serial}",
                    },
                    "csr": csr_id,
                },
            )
            self._json(
                201,
                {
                    "ok": 1,
                    "serial": cert.serial,
                    "subject_id": cert.subject_id,
                    "delegate": cert.delegate,
                    "grants": cert.grants,
                    "csr": csr_id,
                },
            )
            return

        if serial := _param(params, "serial"):
            row = self.board.store.certificate(serial)
            if row is None:
                raise StoreError("certificate not found", 404)
            row["active"] = self.board.store.certificate_active(serial)
            self._json(200, row)
            return
        if subject := _param(params, "subject"):
            if not valid_author_id(subject):
                raise StoreError("invalid subject id", 400)
            rows = self.board.store.certificates_for(subject)
            for row in rows:
                row["active"] = self.board.store.certificate_active(str(row["serial"]))
            self._json(200, rows)
            return
        limit = _int(params, "limit", 50, 1, self.board.cfg.max_limit)
        assert limit is not None
        self._json(
            200,
            self.board.store.list_certificates(
                issuer_id=_param(params, "issuer"),
                limit=limit,
            ),
        )

    def _csr(self, params: Params, method: str) -> None:
        store = self.board.store

        if method == "GET":
            if self._limited(False):
                return
            csr_id = _optional_positive_int(params, "id")
            if csr_id is not None:
                csr = store.csr(csr_id)
                if csr is None:
                    raise StoreError("CSR not found", 404)
                self._json(200, csr)
                return
            limit = _int(params, "limit", 50, 1, self.board.cfg.max_limit)
            assert limit is not None
            self._json(
                200,
                store.list_csrs(
                    status=_param(params, "status"),
                    subject_id=_param(params, "subject"),
                    requested_issuer=_param(params, "requested_issuer"),
                    limit=limit,
                ),
            )
            return

        if method != "POST":
            raise StoreError("POST required", 405)
        if self._limited(True):
            return

        cancel_id = _optional_positive_int(params, "cancel")
        reject_id = _optional_positive_int(params, "reject")
        if cancel_id is not None and reject_id is not None:
            raise StoreError("choose cancel or reject", 400)

        key = _required(params, "key")
        sig = _required(params, "sig")
        canonical_key, signer_id = public_identity(key)
        reason = _param(params, "reason") or ""

        if cancel_id is not None:
            payload = request_payload(
                action="cert.request.cancel",
                signer_id=signer_id,
                version=1,
                csr_id=cancel_id,
                reason=reason,
            )
            auth = signed_request(canonical_key, sig, payload, version=1)
            self._json(200, store.cancel_csr(cancel_id, auth.signer_id, reason))
            return

        if reject_id is not None:
            payload = request_payload(
                action="cert.request.reject",
                signer_id=signer_id,
                version=1,
                csr_id=reject_id,
                reason=reason,
            )
            auth = signed_request(canonical_key, sig, payload, version=1)
            self._json(200, store.reject_csr(reject_id, auth.signer_id, reason))
            return

        grants = _grants(_required(params, "grants"))
        grant_manifest = _grant_manifest(grants)
        requested_issuer = (_param(params, "requested_issuer") or "").lower()
        delegate = _truthy(_param(params, "delegate"))
        message = _param(params, "message") or ""
        nonce = _required(params, "nonce")
        issued = _int_required(params, "issued")
        payload = request_payload(
            action="cert.request",
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            requested_issuer=requested_issuer,
            delegate=delegate,
            csr_grants=grant_manifest,
            message=message,
        )
        auth = signed_request(
            canonical_key,
            sig,
            payload,
            version=1,
            nonce=nonce,
            issued=issued,
        )
        self._json(
            201,
            store.create_csr(
                auth=auth,
                grants=grants,
                delegate=delegate,
                requested_issuer=requested_issuer,
                message=message,
            ),
        )

    def _revoke(self, params: Params) -> None:
        serial = _required(params, "serial")
        key = _required(params, "key")
        sig = _required(params, "sig")
        reason = _param(params, "reason") or ""
        canonical_key, signer_id = public_identity(key)
        payload = request_payload(
            action="cert.revoke",
            signer_id=signer_id,
            version=1,
            serial=serial,
            reason=reason,
        )
        auth = signed_request(canonical_key, sig, payload, version=1)
        certificate = self.board.store.certificate(serial)
        self.board.store.revoke_certificate(serial, auth.signer_id, reason)
        if certificate is not None:
            self.board.webhooks.emit(
                str(certificate["subject_id"]),
                "certificate.revoked",
                {
                    "certificate": {
                        "serial": serial,
                        "issuer_id": str(certificate["issuer_id"]),
                        "subject_id": str(certificate["subject_id"]),
                        "url": f"https://{self.board.cfg.site_name}/_cert?serial={serial}",
                    },
                    "revoked_by": auth.signer_id,
                    "reason": reason,
                },
            )
        self._send(200, render_ok(ok=1, action="revoke", serial=serial, by=auth.signer_id))

    def _policy(self, params: Params) -> None:
        board = _required(params, "board")
        if board != board.lower():
            raise StoreError("channel name must be lowercase", 400)
        anonymous_raw = _param(params, "anonymous")
        permissions_raw = _param(params, "permissions")
        if anonymous_raw is None and permissions_raw is None and _param(params, "sig") is None:
            self._json(200, self.board.store.policy(board))
            return
        if self._limited(True):
            return

        anonymous = _topic_permissions(params)
        key = _required(params, "key")
        sig = _required(params, "sig")
        canonical_key, signer_id = public_identity(key)
        version = int(self.board.store.policy(board)["version"]) + 1
        payload = request_payload(
            action="topic.policy",
            signer_id=signer_id,
            version=version,
            board=board,
            anonymous=anonymous,
        )
        auth = signed_request(canonical_key, sig, payload, version=version)
        if not self.board.store.signed_allowed(auth.signer_id, board, "topic.policy"):
            raise StoreError("certificate does not grant topic.policy", 403)
        self._json(200, self.board.store.set_policy(board, anonymous, version))

    def _like(self, params: Params) -> None:
        requested = (_param(params, "action") or "like").lower()
        if requested not in {"like", "unlike"}:
            raise StoreError("like action must be like or unlike", 400)
        action = "post.like" if requested == "like" else "post.unlike"
        post_id = _post_id(_required(params, "id"))
        post = self.board.store.get_post(post_id)
        if post is None:
            raise StoreError("post not found", 404)

        key = _required(params, "key")
        sig = _required(params, "sig")
        nonce = _required(params, "nonce")
        issued = _int_required(params, "issued")
        canonical_key, signer_id = public_identity(key)
        payload = request_payload(
            action=action,
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            post_id=post.id,
        )
        auth = signed_request(
            canonical_key,
            sig,
            payload,
            version=1,
            nonce=nonce,
            issued=issued,
        )
        if self.board.store.key_info(auth.signer_id) is None:
            raise StoreError("like requires an established signed identity", 403)
        self.board.store.consume_nonce(auth)
        changed, likes = self.board.store.set_post_like(
            post.id,
            auth.signer_id,
            requested == "like",
        )
        if self.board.engagement.available:
            self.board.engagement.set_likes(post.id, post.board, likes)
        self._send(
            200,
            render_ok(
                ok=1,
                action=requested,
                id=post.id,
                liked=1 if requested == "like" else 0,
                changed=1 if changed else 0,
                likes=likes,
                author_id=auth.signer_id,
            ),
        )

    def _inbox(self, params: Params) -> None:
        key = _required(params, "key")
        sig = _required(params, "sig")
        canonical_key, signer_id = public_identity(key)
        nonce = _required(params, "nonce")
        issued = _int_required(params, "issued")
        since, before, limit = _inbox_window(params, self.board.cfg)
        payload = request_payload(
            action="inbox.read",
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            since=since,
            before=before,
            limit=limit,
        )
        auth = signed_request(
            canonical_key,
            sig,
            payload,
            version=1,
            nonce=nonce,
            issued=issued,
        )
        self.board.store.consume_nonce(auth)
        events = self.board.store.inbox(
            auth.signer_id,
            since=since,
            before=before,
            limit=limit,
        )
        receipts = self.board.exchange.receipts_for(
            auth.signer_id,
            [post.id for post, _kinds in events],
        )
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            lines = []
            for post, kinds in events:
                lines.append(
                    json.dumps(
                        {
                            "kinds": list(kinds),
                            "ack": receipts.get(post.id, "delivered"),
                            "ref": f"post:{post.id}",
                            "post": post.to_dict(),
                            "authentication": self.board.store.post_authentication(post),
                        },
                        ensure_ascii=False,
                    )
                )
            self._send(
                200,
                "\n".join(lines) + ("\n" if lines else ""),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return
        self._send(
            200,
            render_inbox(
                auth.signer_id,
                events,
                latest_id=self.board.store.stats()["latest_id"],
                authentications={
                    post.id: self.board.store.post_authentication(post) for post, _ in events
                },
                receipts=receipts,
            ),
        )

    def _exchange(self, head: str, params: Params) -> None:
        action = _required(params, "action")
        if not _exchange_action_for_head(head, action):
            raise StoreError(f"{action or 'missing action'} is not valid for /{head}", 400)

        key = _required(params, "key")
        sig = _required(params, "sig")
        canonical_key, signer_id = public_identity(key)
        payload, meta = _exchange_signing_spec(
            self.board,
            action,
            signer_id,
            params,
            signing=False,
        )
        nonce = str(meta["nonce"])
        issued = int(meta["issued"])
        auth = signed_request(
            canonical_key,
            sig,
            payload,
            version=1,
            nonce=nonce,
            issued=issued,
        )
        self.board.store.consume_nonce(auth)
        service = self.board.exchange

        if action == "outbox.read":
            limit = int(meta["limit"])
            posts = self.board.store.list_posts(
                author_id=auth.signer_id,
                since=meta["since"],
                before=meta["before"],
                limit=limit,
                order="desc",
            )
            posts = [post for post in posts if not post.system and post.custody_id is None]
            fmt = (_param(params, "format") or "ndjson").lower()
            authentications = {
                post.id: self.board.store.post_authentication(post) for post in posts
            }
            tags = self.board.store.tags_for_posts([post.id for post in posts])
            if fmt == "json":
                self._json(
                    200,
                    [
                        {
                            **post.to_dict(),
                            "authentication": authentications[post.id],
                            "tags": list(tags.get(post.id, ())),
                        }
                        for post in posts
                    ],
                )
                return
            if fmt != "ndjson":
                raise StoreError("outbox format must be json or ndjson", 400)
            self._send(
                200,
                posts_to_ndjson(posts, authentications=authentications, tags=tags),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return

        if action == "state.read":
            self._json(200, service.state_read(auth.signer_id, meta["name"]))
            return
        if action == "state.write":
            self._json(
                200,
                service.state_write(
                    auth.signer_id,
                    str(meta["name"]),
                    str(meta["value"]),
                ),
            )
            return
        if action == "state.delete":
            self._json(200, service.state_delete(auth.signer_id, str(meta["name"])))
            return

        if action == "watch.add":
            self._json(
                201,
                service.watch_add(
                    auth.signer_id,
                    str(meta["kind"]),
                    str(meta["target"]),
                ),
            )
            return
        if action == "watch.delete":
            self._json(200, service.watch_delete(auth.signer_id, str(meta["id"])))
            return
        if action == "watch.list":
            self._json(200, service.watch_list(auth.signer_id))
            return

        if action == "inbox.ack":
            self._json(
                200,
                service.ack(
                    auth.signer_id,
                    int(meta["id"]),
                    str(meta["status"]),
                ),
            )
            return

        if action == "task.open":
            self._json(201, service.task_open(auth.signer_id, int(meta["id"])))
            return
        if action == "task.claim":
            self._json(200, service.task_claim(auth.signer_id, int(meta["id"])))
            return
        if action == "task.release":
            self._json(200, service.task_release(auth.signer_id, int(meta["id"])))
            return
        if action == "task.complete":
            self._json(200, service.task_complete(auth.signer_id, int(meta["id"])))
            return
        if action == "task.list":
            self._json(
                200,
                service.task_list(
                    auth.signer_id,
                    scope=str(meta["scope"] or "open"),
                    limit=int(meta["limit"]),
                ),
            )
            return

        raise StoreError("unsupported exchange action", 400)

    def _webhook(self, params: Params) -> None:
        action = _required(params, "action")
        if not action.startswith("webhook."):
            raise StoreError("invalid webhook action", 400)

        key = _required(params, "key")
        sig = _required(params, "sig")
        nonce = _required(params, "nonce")
        issued = _int_required(params, "issued")
        canonical_key, signer_id = public_identity(key)
        webhook_id, webhook_url, webhook_events, webhook_enabled = _webhook_fields(
            params,
            action,
        )
        payload = request_payload(
            action=action,
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            webhook_id=webhook_id,
            webhook_url=webhook_url,
            webhook_events=webhook_events,
            webhook_enabled=webhook_enabled,
        )
        auth = signed_request(
            canonical_key,
            sig,
            payload,
            version=1,
            nonce=nonce,
            issued=issued,
        )
        self.board.store.consume_nonce(auth)

        service = self.board.webhooks
        if action == "webhook.create":
            self._json(201, service.create(auth.signer_id, webhook_url, webhook_events))
            return
        if action == "webhook.list":
            self._json(200, service.list(auth.signer_id))
            return
        if action == "webhook.update":
            self._json(
                200,
                service.update(
                    auth.signer_id,
                    webhook_id,
                    url=webhook_url,
                    events=webhook_events,
                    enabled=webhook_enabled,
                ),
            )
            return
        if action == "webhook.delete":
            service.delete(auth.signer_id, webhook_id)
            self._json(200, {"ok": 1, "id": webhook_id})
            return
        if action == "webhook.rotate":
            self._json(200, service.rotate(auth.signer_id, webhook_id))
            return
        if action == "webhook.test":
            delivery_id = service.test(auth.signer_id, webhook_id)
            self._json(
                202,
                {
                    "ok": 1,
                    "event": "webhook.test",
                    "webhook_id": webhook_id,
                    "delivery_id": delivery_id,
                },
            )
            return
        raise StoreError("unsupported webhook action", 400)

    def _profile_update(self, params: Params) -> None:
        key = _required(params, "key")
        sig = _required(params, "sig")
        nonce = _required(params, "nonce")
        issued = _int_required(params, "issued")
        canonical_key, signer_id = public_identity(key)
        current = self.board.store.profile_by_author(signer_id)
        if current is None:
            raise StoreError("profile/name claim not found; publish a signed post first", 404)
        name = _param(params, "name") or str(current["name"])
        claim = self.board.store.name_claim(name)
        if claim is None or str(claim["author_id"]) != signer_id:
            raise StoreError("profile name must be claimed by this public key", 403)
        name = str(claim["display_name"])
        bio = _param(params, "bio")
        if bio is None:
            bio = str(current["bio"])
        version = self.board.store.profile_version(signer_id) + 1
        payload = request_payload(
            action="profile.update",
            signer_id=signer_id,
            version=version,
            nonce=nonce,
            issued=issued,
            profile_name=name,
            profile_bio=bio,
            profile_public_key=canonical_key,
        )
        auth = signed_request(
            canonical_key,
            sig,
            payload,
            version=version,
            nonce=nonce,
            issued=issued,
        )
        info = payload_info(payload)
        self._json(
            200,
            self.board.store.update_profile(
                auth=auth,
                name=name,
                bio=bio,
                payload_b64=info["payload_b64"],
            ),
        )

    def _path_get(self, method: str, segments: list[str], params: Params) -> None:
        if method == "HEAD":
            self._send(
                405,
                render_error(405, "HEAD cannot execute path GET operations"),
                extra_headers={"Allow": "GET"},
            )
            return
        if method != "GET":
            self._send(
                405,
                render_error(405, "path GET protocol only accepts GET"),
                extra_headers={"Allow": "GET"},
            )
            return
        if params:
            raise StoreError("path GET protocol does not accept query parameters", 400)

        if len(segments) in {1, 2}:
            if len(segments) == 2 and segments[1] != "v1":
                self._error(404, "unknown path GET protocol version")
                return
            self._send(200, _path_get_help(self.board.cfg))
            return
        if segments[1] != "v1":
            self._error(404, "unknown path GET protocol version")
            return

        if len(segments) == 3:
            operation, request_id, bridge_params, payload_sha256 = _decode_path_get_payload(
                segments[2],
                self.board.cfg,
            )
            self._execute_path_get(
                operation,
                request_id,
                bridge_params,
                payload_sha256,
                large=False,
            )
            return

        mode = segments[2]
        if mode == "chunk":
            self._path_get_chunk(segments)
            return
        if mode == "status":
            self._path_get_status(segments)
            return
        if mode == "commit":
            self._path_get_commit(segments)
            return
        self._error(
            404,
            "invalid path GET v1 route",
            "use /g/v1/PAYLOAD or /g/v1/chunk|status|commit/...",
        )

    def _path_get_chunk(self, segments: list[str]) -> None:
        if len(segments) != 7:
            self._error(
                404,
                "invalid path GET chunk route",
                "use /g/v1/chunk/RID/INDEX/TOTAL/BASE64URL_CHUNK",
            )
            return
        request_id = segments[3]
        if not PATH_GET_CHUNK_REQUEST_ID_RE.fullmatch(request_id):
            raise StoreError(
                "chunked path GET rid must be 22..64 base64url-safe characters",
                400,
            )
        try:
            chunk_index = int(segments[4], 10)
            chunk_count = int(segments[5], 10)
        except ValueError as exc:
            raise StoreError("path GET chunk index and total must be integers", 400) from exc
        if not 1 <= chunk_count <= self.board.cfg.path_max_chunks:
            raise StoreError(
                f"path GET chunk total must be 1..{self.board.cfg.path_max_chunks}",
                400,
            )
        if not 0 <= chunk_index < chunk_count:
            raise StoreError("path GET chunk index must be zero-based and smaller than total", 400)

        data = _decode_path_get_bytes(
            segments[6],
            self.board.cfg.max_path_payload_bytes,
            "path GET chunk",
        )
        if self._limited_path_chunk():
            return
        state = self.board.store.put_path_get_chunk(
            request_id=request_id,
            chunk_index=chunk_index,
            chunk_count=chunk_count,
            data=data,
            max_total_bytes=self.board.cfg.max_path_transfer_bytes,
            ttl_seconds=self.board.cfg.path_chunk_ttl_seconds,
        )
        replay = bool(state["replay"])
        self._send(
            200 if replay else 201,
            render_ok(
                ok=1,
                state="chunk",
                request_id=request_id,
                index=chunk_index,
                total=chunk_count,
                received=state["received"],
                bytes=state["bytes"],
                replay=1 if replay else 0,
            ),
            extra_headers={
                "Cache-Control": "no-store",
                "X-Path-GET-Request-ID": request_id,
                "X-Path-GET-Chunk-Replay": "1" if replay else "0",
            },
        )

    def _path_get_status(self, segments: list[str]) -> None:
        if len(segments) != 4:
            self._error(404, "invalid path GET status route", "use /g/v1/status/RID")
            return
        request_id = segments[3]
        if not PATH_GET_REQUEST_ID_RE.fullmatch(request_id):
            raise StoreError("invalid path GET request id", 400)
        if self._limited(False):
            return

        receipt = self.board.store.path_get_receipt(request_id)
        if receipt is not None:
            self._send(
                200,
                render_ok(
                    ok=1,
                    state="complete" if receipt["completed"] else "executing",
                    request_id=request_id,
                    operation=receipt["operation"],
                    payload_sha256=receipt["payload_sha256"],
                ),
                extra_headers={
                    "Cache-Control": "no-store",
                    "X-Path-GET-Request-ID": request_id,
                },
            )
            return

        state, _ = self.board.store.path_get_chunk_state(
            request_id,
            ttl_seconds=self.board.cfg.path_chunk_ttl_seconds,
            max_total_bytes=self.board.cfg.max_path_transfer_bytes,
        )
        if state is None:
            raise StoreError("path GET chunk transfer not found or expired", 404)
        missing = _format_chunk_ranges(state["missing"])
        self._send(
            200,
            render_ok(
                ok=1,
                state="ready" if not state["missing"] else "receiving",
                request_id=request_id,
                received=state["received"],
                total=state["total"],
                bytes=state["bytes"],
                missing=missing or None,
            ),
            extra_headers={
                "Cache-Control": "no-store",
                "X-Path-GET-Request-ID": request_id,
            },
        )

    def _path_get_commit(self, segments: list[str]) -> None:
        if len(segments) != 5:
            self._error(
                404,
                "invalid path GET commit route",
                "use /g/v1/commit/RID/SHA256",
            )
            return
        request_id = segments[3]
        expected_sha256 = segments[4]
        if not PATH_GET_CHUNK_REQUEST_ID_RE.fullmatch(request_id):
            raise StoreError(
                "chunked path GET rid must be 22..64 base64url-safe characters",
                400,
            )
        if not PATH_GET_SHA256_RE.fullmatch(expected_sha256):
            raise StoreError("path GET commit SHA256 must be 64 lowercase hex characters", 400)

        if self._replay_path_get(request_id, expected_sha256):
            return
        if self._limited(True):
            return

        state, raw = self.board.store.path_get_chunk_state(
            request_id,
            ttl_seconds=self.board.cfg.path_chunk_ttl_seconds,
            max_total_bytes=self.board.cfg.max_path_transfer_bytes,
        )
        if state is None:
            raise StoreError("path GET chunk transfer not found or expired", 404)
        if raw is None:
            self._send(
                409,
                render_ok(
                    error="path GET transfer is incomplete",
                    status=409,
                    request_id=request_id,
                    received=state["received"],
                    total=state["total"],
                    missing=_format_chunk_ranges(state["missing"]),
                ),
                extra_headers={"X-Path-GET-Request-ID": request_id},
            )
            return

        payload_sha256 = hashlib.sha256(raw).hexdigest()
        if payload_sha256 != expected_sha256:
            raise StoreError(
                "path GET assembled payload SHA256 does not match commit path",
                409,
            )
        operation, embedded_id, bridge_params, decoded_sha256 = _decode_path_get_raw(
            raw,
            self.board.cfg,
            max_bytes=self.board.cfg.max_path_transfer_bytes,
        )
        if embedded_id != request_id:
            raise StoreError("path GET chunk rid must match payload rid", 409)
        if decoded_sha256 != expected_sha256:
            raise StoreError("path GET payload SHA256 changed during decode", 409)

        self._execute_path_get(
            operation,
            request_id,
            bridge_params,
            payload_sha256,
            large=True,
            rate_limit=False,
        )

    def _replay_path_get(self, request_id: str, payload_sha256: str) -> bool:
        existing = self.board.store.path_get_receipt(request_id)
        if existing is None:
            return False
        if existing["payload_sha256"] != payload_sha256:
            raise StoreError(
                "path GET request id was reused with different payload",
                409,
            )
        if existing["completed"]:
            headers = dict(existing["headers"])
            headers.update(
                {
                    "X-Path-GET-Request-ID": request_id,
                    "X-Path-GET-Replay": "1",
                }
            )
            self._send(
                int(existing["status"]),
                existing["body"],
                content_type=str(existing["content_type"]),
                extra_headers=headers,
            )
        else:
            self._send(
                409,
                render_ok(
                    error="path GET request is already in progress",
                    status=409,
                    request_id=request_id,
                    retry="same URL",
                ),
                extra_headers={
                    "Retry-After": "1",
                    "X-Path-GET-Request-ID": request_id,
                },
            )
        return True

    def _execute_path_get(
        self,
        operation: str,
        request_id: str,
        bridge_params: Params,
        payload_sha256: str,
        *,
        large: bool,
        rate_limit: bool = True,
    ) -> None:
        if self._replay_path_get(request_id, payload_sha256):
            return
        if rate_limit and self._limited(True):
            return

        store = self.board.store
        claimed, existing = store.claim_path_get(
            request_id=request_id,
            payload_sha256=payload_sha256,
            operation=operation,
        )
        if not claimed:
            if existing is not None and existing["completed"]:
                headers = dict(existing["headers"])
                headers.update(
                    {
                        "X-Path-GET-Request-ID": request_id,
                        "X-Path-GET-Replay": "1",
                    }
                )
                self._send(
                    int(existing["status"]),
                    existing["body"],
                    content_type=str(existing["content_type"]),
                    extra_headers=headers,
                )
                return
            self._send(
                409,
                render_ok(
                    error="path GET request is already in progress",
                    status=409,
                    request_id=request_id,
                    retry="same URL",
                ),
                extra_headers={
                    "Retry-After": "1",
                    "X-Path-GET-Request-ID": request_id,
                },
            )
            return

        capture: dict[str, Any] = {}
        self._path_get_capture = capture
        try:
            self._dispatch_path_get(operation, bridge_params, large=large)
        except Exception:
            store.abort_path_get(request_id, payload_sha256)
            raise
        finally:
            self._path_get_capture = None

        if not capture:
            store.abort_path_get(request_id, payload_sha256)
            raise StoreError("path GET operation produced no response", 500)

        status = int(capture["status"])
        body = bytes(capture["body"])
        content_type = str(capture["content_type"])
        headers = dict(capture["headers"])
        store.complete_path_get(
            request_id=request_id,
            payload_sha256=payload_sha256,
            status=status,
            content_type=content_type,
            body=body,
            headers=headers,
        )
        if large:
            store.delete_path_get_chunks(request_id)
            headers["X-Path-GET-Transfer"] = "chunked"
        headers.update(
            {
                "X-Path-GET-Request-ID": request_id,
                "X-Path-GET-Replay": "0",
            }
        )
        self._send(status, body, content_type=content_type, extra_headers=headers)

    def _dispatch_path_get(
        self,
        operation: str,
        params: Params,
        *,
        large: bool,
    ) -> None:
        method = "POST" if large else "GET"
        if operation.startswith("guest."):
            self._guest_bridge(operation.removeprefix("guest."), params, method)
            return
        if operation == "post.create":
            self._create(params, (), method)
            return
        post_id = _post_id(_required(params, "id"))
        if operation == "post.edit":
            self._edit(post_id, params, (), method)
            return
        if operation == "post.delete":
            self._delete(post_id, params)
            return
        raise StoreError("unsupported path GET operation", 400)

    def _guest_bridge(self, action: str, params: Params, method: str = "GET") -> None:
        if action in {"like", "unlike"}:
            info = store.custody_info(token)
            post_id = _post_id(_required(params, "id"))
            post = store.get_post(post_id)
            if post is None:
                raise StoreError("post not found", 404)
            changed, likes = store.set_post_like(
                post.id,
                str(info["author_id"]),
                action == "like",
            )
            if self.board.engagement.available:
                self.board.engagement.set_likes(post.id, post.board, likes)
            self._send(
                200,
                render_ok(
                    ok=1,
                    action=action,
                    id=post.id,
                    liked=1 if action == "like" else 0,
                    changed=1 if changed else 0,
                    likes=likes,
                    auth="custodial",
                    author_id=info["author_id"],
                ),
            )
            return

        if action == "post":
            self._create({**params, "board": ["guest"]}, (), method)
            return
        post_id = _post_id(_required(params, "id"))
        post = self.board.store.get_post(post_id)
        if post is None or post.board != "guest":
            raise StoreError("guest post not found", 404)
        if action == "edit":
            self._edit(post_id, params, (), method)
            return
        self._delete(post_id, params)

    def _custody(self, action: str, params: Params) -> None:
        store = self.board.store
        if action == "new":
            self._json(201, store.create_custody_identity(_param(params, "name") or "guest"))
            return

        token = _required(params, "token")
        if action == "rotate":
            self._json(200, store.rotate_custody_token(token))
            return
        if action == "me":
            self._json(200, store.custody_info(token))
            return

        if action == "post":
            info = store.custody_info(token)
            body, title, name, _ = store.prepare_post(
                body=_required(params, "text"),
                title=_param(params, "title") or "",
                name=str(info["name"]),
                max_body_bytes=self.board.cfg.max_post_bytes,
            )
            _, reply_to = _create_context({**params, "board": ["custody"]}, store)
            nonce = secrets.token_hex(16)
            issued = int(time.time())
            payload = request_payload(
                action="post.create",
                signer_id=str(info["author_id"]),
                version=1,
                nonce=nonce,
                issued=issued,
                board="custody",
                name=name,
                title=title,
                body=body,
                files=(),
                reply_to=reply_to,
            )
            auth, custody_id = store.custody_auth(
                token,
                payload,
                version=1,
                nonce=nonce,
                issued=issued,
            )
            post, evicted = store.create_post(
                board="custody",
                body=body,
                name=name,
                title=title,
                auth=auth,
                max_body_bytes=self.board.cfg.max_post_bytes,
                reply_to=reply_to,
                custody_id=custody_id,
            )
            if self.board.engagement.available:
                self.board.engagement.set_comments(post.id, post.board, 0)
                self._sync_reply_count(reply_to)
            self._emit_post_created(post)
            self._send(
                201,
                render_ok(
                    ok=1,
                    action="create",
                    id=post.id,
                    board="custody",
                    auth="custodial",
                    author_id=post.author_id,
                    evicted=evicted or None,
                    url=f"https://{self.board.cfg.site_name}/custody/{post.id}",
                ),
            )
            return

        post_id = _post_id(_required(params, "id"))
        post = store.get_post_or_archived(post_id) if action == "purge" else store.get_post(post_id)
        if post is None or post.board != "custody":
            raise StoreError("custody post not found", 404)
        if not store.custody_owns(token, post):
            raise StoreError("custody token does not own this post", 403)

        if action == "delete":
            parent_id = post.reply_to
            store.archive_post(post, actor_id=post.author_id)
            self.board.engagement.remove_post(post.id, post.board)
            self._sync_reply_count(parent_id)
            self._emit_post_deleted(post, post.author_id, archived=True)
            self._send(
                200,
                render_ok(
                    ok=1,
                    action="delete",
                    archived=1,
                    id=post_id,
                    auth="custodial",
                ),
            )
            return

        if action == "purge":
            reason = " ".join(_required(params, "reason").split())[:500]
            if not reason:
                raise StoreError("purge reason is required", 400)
            parent_id = post.reply_to
            purged = store.purge_post(post.id, actor_id=post.author_id, reason=reason)
            if purged is None:
                raise StoreError("custody post not found", 404)
            self.board.engagement.remove_post(post.id, post.board)
            self._sync_reply_count(parent_id)
            self._emit_post_deleted(post, post.author_id, purged=True)
            self._send(
                200,
                render_ok(
                    ok=1,
                    action="purge",
                    purged=1,
                    id=post_id,
                    auth="custodial",
                ),
            )
            return

        info = store.custody_info(token)
        body, title, name, _ = store.prepare_post(
            body=_required(params, "text"),
            title=post.title if _param(params, "title") is None else _param(params, "title") or "",
            name=str(info["name"]),
            max_body_bytes=self.board.cfg.max_post_bytes,
        )
        version = post.sig_version + 1
        payload = request_payload(
            action="post.edit",
            signer_id=str(info["author_id"]),
            version=version,
            post_id=post.id,
            owner_id=post.author_id or "",
            board="custody",
            name=name,
            title=title,
            body=body,
            files=(),
            reply_to=post.reply_to,
        )
        auth, _ = store.custody_auth(token, payload, version=version)
        updated = store.edit_post(
            post=post,
            body=body,
            name=name,
            title=title,
            auth=auth,
            files=(),
            max_body_bytes=self.board.cfg.max_post_bytes,
        )
        self._emit_post_updated(updated)
        self._send(
            200,
            render_ok(
                ok=1,
                action="edit",
                id=updated.id,
                board="custody",
                auth="custodial",
                version=updated.sig_version,
            ),
        )

    def _users(self, params: Params) -> None:
        limit = _int(params, "limit", 100, 1, self.board.cfg.max_limit)
        assert limit is not None
        users = self.board.store.list_users(limit)
        fmt = (_param(params, "format") or "").lower()
        if fmt == "json":
            self._json(200, users)
            return
        if fmt == "ndjson":
            self._send(
                200,
                "".join(json.dumps(user, ensure_ascii=False) + "\n" for user in users),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return
        self._send(200, render_users(users))

    def _user_posts(self, username: str, params: Params) -> None:
        limit = _int(params, "limit", self.board.cfg.default_limit, 1, self.board.cfg.max_limit)
        assert limit is not None
        sort = (_param(params, "sort") or "new").lower()
        if sort not in {"new", "newest", "desc", "old", "oldest", "asc"}:
            raise StoreError("user post sort must be new or old", 400)
        if _param(params, "cursor"):
            raise StoreError("user time streams use server-returned before/since links", 400)
        order = "asc" if sort in {"old", "oldest", "asc"} else "desc"
        profile, posts = self.board.store.posts_by_username(
            username,
            since=_int(params, "since", None, 0, None),
            before=_int(params, "before", None, 0, None),
            limit=limit + 1,
            order=order,
        )
        truncated = len(posts) > limit
        posts = posts[:limit]
        next_url = _next_time_url(
            f"/users/{quote(str(profile['name']), safe='')}",
            params,
            posts,
            limit=limit,
            order=order,
            has_more=truncated,
        )
        page_direction = "newer" if order == "asc" else "older"
        page = _page_meta(posts, next_url=next_url, direction=page_direction)
        authentications = {post.id: self.board.store.post_authentication(post) for post in posts}
        engagement = self._engagement_map(posts)
        tags = self.board.store.tags_for_posts([post.id for post in posts])
        fmt = (_param(params, "format") or "").lower()
        if fmt in {"json", "ndjson"}:
            if fmt == "json":
                self._json(
                    200,
                    {
                        "user": profile,
                        "posts": [
                            {
                                **post.to_dict(),
                                "authentication": authentications.get(post.id),
                                "engagement": (engagement or {}).get(post.id),
                                "tags": list(tags.get(post.id, ())),
                            }
                            for post in posts
                        ],
                        "page": page,
                    },
                )
            else:
                self._send(
                    200,
                    posts_to_ndjson(posts, authentications, engagement, tags, page),
                    content_type="application/x-ndjson; charset=utf-8",
                )
            return

        self._send(
            200,
            render_listing(
                board=None,
                posts=posts,
                full=(_param(params, "view") or "").lower() == "full",
                truncated=truncated,
                next_url=next_url,
                page_direction=page_direction,
                note=(
                    f"signed user @{profile['name']} · "
                    f"author_id={profile['author_id']} · profile=/@{profile['name']}"
                ),
                authentications=authentications,
                engagement=engagement,
                tags=tags,
                heading=f"# /users/{profile['name']}",
            ),
        )

    def _tags(self, params: Params) -> None:
        limit = _int(params, "limit", 50, 1, self.board.cfg.max_limit)
        assert limit is not None
        tags = self.board.store.list_tags(limit)
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            if (_param(params, "format") or "").lower() == "ndjson":
                self._send(
                    200,
                    "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in tags),
                    content_type="application/x-ndjson; charset=utf-8",
                )
            else:
                self._json(200, tags)
            return
        self._send(200, render_tags(tags))

    def _tag_view(self, tag: str, params: Params) -> None:
        normalized = self.board.store.normalize_tag(tag)
        info = self.board.store.tag_info(normalized)
        if info is None:
            self._error(404, f"no such hashtag: #{normalized}", "try /tags")
            return

        limit = _int(params, "limit", self.board.cfg.default_limit, 1, self.board.cfg.max_limit)
        assert limit is not None
        sort = (_param(params, "sort") or "new").lower()
        if sort not in {"new", "newest", "desc", "old", "oldest", "asc"}:
            raise StoreError("tag sort must be new or old", 400)
        if _param(params, "cursor"):
            raise StoreError("tag time streams use server-returned before/since links", 400)
        order = "asc" if sort in {"old", "oldest", "asc"} else "desc"
        posts = self.board.store.posts_by_tag(
            normalized,
            since=_int(params, "since", None, 0, None),
            before=_int(params, "before", None, 0, None),
            limit=limit + 1,
            order=order,
        )
        truncated = len(posts) > limit
        posts = posts[:limit]
        next_url = _next_time_url(
            f"/tag/{quote(normalized, safe='')}",
            params,
            posts,
            limit=limit,
            order=order,
            has_more=truncated,
        )
        page_direction = "newer" if order == "asc" else "older"
        page = _page_meta(posts, next_url=next_url, direction=page_direction)
        authentications = {post.id: self.board.store.post_authentication(post) for post in posts}
        engagement = self._engagement_map(posts)
        tags = self.board.store.tags_for_posts([post.id for post in posts])

        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(posts, authentications, engagement, tags, page),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return

        self._send(
            200,
            render_listing(
                board=None,
                posts=posts,
                full=(_param(params, "view") or "").lower() == "full",
                truncated=truncated,
                next_url=next_url,
                page_direction=page_direction,
                note=(
                    f"hashtag #{normalized} · {int(info['posts'])} posts · "
                    f"{int(info['boards'])} boards"
                ),
                authentications=authentications,
                engagement=engagement,
                tags=tags,
                heading=f"# /tag/{normalized}",
            ),
        )

    def _send_index_page(
        self,
        *,
        fmt: str,
        kind: str,
        order: str,
        next_url: str | None,
        items: list[dict[str, Any]],
        text_body: str,
    ) -> None:
        meta = {
            "type": "index-page",
            "index": kind,
            "order": order,
            "next": next_url,
        }
        if fmt == "json":
            self._json(200, {**meta, "items": items})
            return
        if fmt == "ndjson":
            body = json.dumps(meta, ensure_ascii=False) + "\n"
            body += "".join(
                json.dumps({"type": "entry", **item}, ensure_ascii=False) + "\n" for item in items
            )
            self._send(
                200,
                body,
                content_type="application/x-ndjson; charset=utf-8",
            )
            return
        self._send(200, text_body)

    def _index(self, segments: list[str], params: Params) -> None:
        store = self.board.store
        fmt = (_param(params, "format") or "").lower()
        if fmt not in {"", "json", "ndjson"}:
            raise StoreError("format must be json or ndjson", 400)

        manifest = [
            {
                "name": "by-id",
                "href": "/index/by-id",
                "key": "id",
                "description": "posts ordered by stable numeric id",
            },
            {
                "name": "by-time",
                "href": "/index/by-time",
                "key": "created,id",
                "description": "posts ordered by creation time",
            },
            {
                "name": "by-updated",
                "href": "/index/by-updated",
                "key": "updated,id",
                "description": "posts ordered by last update time",
            },
            {
                "name": "by-name",
                "href": "/index/by-name",
                "key": "bound signed name",
                "description": "claimed signed names ordered alphabetically",
            },
            {
                "name": "by-author",
                "href": "/index/by-author",
                "key": "author_id",
                "description": "signed identities ordered by author id",
            },
            {
                "name": "by-board",
                "href": "/index/by-board",
                "key": "board name",
                "description": "boards ordered alphabetically",
            },
            {
                "name": "by-tag",
                "href": "/index/by-tag",
                "key": "normalized hashtag",
                "description": "hashtags ordered alphabetically",
            },
            {
                "name": "by-reply",
                "href": "/index/by-reply",
                "key": "parent post id",
                "description": "reply groups ordered by parent post id",
            },
        ]

        if len(segments) == 1:
            if fmt == "json":
                self._json(
                    200,
                    {
                        "type": "index-root",
                        "version": __version__,
                        "indexes": manifest,
                        "views": {
                            "latest": "/latest",
                            "search": "/_search?q=TEXT",
                            "hot": "/hot",
                            "rss": "/rss.xml",
                            "tags_by_popularity": "/tags",
                            "users_by_activity": "/users",
                        },
                    },
                )
                return
            if fmt == "ndjson":
                body = "".join(
                    json.dumps({"type": "index", **item}, ensure_ascii=False) + "\n"
                    for item in manifest
                )
                self._send(
                    200,
                    body,
                    content_type="application/x-ndjson; charset=utf-8",
                )
                return
            self._send(200, render_agent_index(self.board.cfg))
            return

        kinds = {
            "by-id",
            "by-time",
            "by-updated",
            "by-name",
            "by-author",
            "by-board",
            "by-tag",
            "by-reply",
        }
        if len(segments) != 2 or segments[1] not in kinds:
            self._error(
                404,
                "unknown index",
                "see /index for available index dimensions",
            )
            return

        kind = segments[1]
        limit = _int(
            params,
            "limit",
            min(50, self.board.cfg.max_limit),
            1,
            self.board.cfg.max_limit,
        )
        assert limit is not None
        default_order = "desc" if kind in {"by-time", "by-updated"} else "asc"
        order = (_param(params, "order") or default_order).lower()
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)

        path = f"/index/{kind}"
        scope = _pagination_scope(path, params, exclude={"format"})
        cursor = _decode_cursor(
            _param(params, "cursor"),
            kind=f"index-{kind}",
            scope=scope,
        )

        if kind in {"by-id", "by-time", "by-updated"}:
            if kind == "by-id":
                boundary = cursor.get("id")
                if boundary is not None and (not isinstance(boundary, int) or boundary < 1):
                    raise StoreError("invalid by-id cursor", 400)
                posts = store.list_posts(
                    since=boundary if order == "asc" else None,
                    before=boundary if order == "desc" else None,
                    limit=limit + 1,
                    order=order,
                )
            else:
                timestamp_field = "created" if kind == "by-time" else "updated"
                timestamp_cursor: tuple[float, int] | None = None
                if cursor:
                    try:
                        timestamp_cursor = (
                            float(cursor[timestamp_field]),
                            int(cursor["id"]),
                        )
                    except (KeyError, TypeError, ValueError) as exc:
                        raise StoreError(f"invalid {kind} cursor", 400) from exc
                    if timestamp_cursor[1] < 1:
                        raise StoreError(f"invalid {kind} cursor", 400)
                if kind == "by-time":
                    posts = store.list_posts_by_time(
                        cursor=timestamp_cursor,
                        limit=limit + 1,
                        order=order,
                    )
                else:
                    posts = store.list_posts_by_updated(
                        cursor=timestamp_cursor,
                        limit=limit + 1,
                        order=order,
                    )

            truncated = len(posts) > limit
            posts = posts[:limit]
            next_cursor = None
            if truncated and posts:
                values: dict[str, int | str] = {"id": posts[-1].id}
                if kind == "by-time":
                    values["created"] = repr(posts[-1].created)
                elif kind == "by-updated":
                    values["updated"] = repr(posts[-1].updated)
                next_cursor = _encode_cursor(f"index-{kind}", scope, **values)
            next_url = _next_cursor_url(
                path,
                params,
                cursor=next_cursor,
                limit=limit,
                has_more=truncated,
            )
            items = [
                {
                    "id": post.id,
                    "path": f"/{post.board}/{post.id}",
                    "board": post.board,
                    "name": post.name,
                    "title": post.title,
                    "created": round(post.created, 3),
                    "updated": round(post.updated, 3),
                }
                for post in posts
            ]
            self._send_index_page(
                fmt=fmt,
                kind=kind,
                order=order,
                next_url=next_url,
                items=items,
                text_body=render_post_index(
                    kind,
                    posts,
                    order=order,
                    next_url=next_url,
                ),
            )
            return

        if kind == "by-name":
            name_cursor = cursor.get("key") if cursor else None
            if name_cursor is not None and not isinstance(name_cursor, str):
                raise StoreError("invalid by-name cursor", 400)
            names = store.list_bound_names(
                cursor_key=name_cursor,
                limit=limit + 1,
                order=order,
            )
            truncated = len(names) > limit
            names = names[:limit]
            next_cursor = (
                _encode_cursor(f"index-{kind}", scope, key=str(names[-1]["name_key"]))
                if truncated and names
                else None
            )
            next_url = _next_cursor_url(
                path,
                params,
                cursor=next_cursor,
                limit=limit,
                has_more=truncated,
            )
            items = [
                {
                    "name": str(item["name"]),
                    "profile": str(item["profile"]),
                    "author_id": str(item["author_id"]),
                    "posts": int(item["posts"]),
                    "claimed": item["claimed"],
                    "last_used": item["last_used"],
                }
                for item in names
            ]
            self._send_index_page(
                fmt=fmt,
                kind=kind,
                order=order,
                next_url=next_url,
                items=items,
                text_body=render_name_index(names, order=order, next_url=next_url),
            )
            return

        key_cursor = cursor.get("key") if cursor else None
        if kind == "by-reply":
            reply_cursor = cursor.get("id") if cursor else None
            if reply_cursor is not None and (not isinstance(reply_cursor, int) or reply_cursor < 1):
                raise StoreError("invalid by-reply cursor", 400)
            entries = store.list_reply_groups(
                cursor_id=reply_cursor,
                limit=limit + 1,
                order=order,
            )
            cursor_value = int(entries[limit - 1]["parent_id"]) if len(entries) > limit else None
        else:
            if key_cursor is not None and not isinstance(key_cursor, str):
                raise StoreError(f"invalid {kind} cursor", 400)
            if kind == "by-tag":
                entries = store.list_tags_by_name(
                    cursor_key=key_cursor,
                    limit=limit + 1,
                    order=order,
                )
                cursor_field = "tag"
            elif kind == "by-board":
                entries = store.list_boards_by_name(
                    cursor_key=key_cursor,
                    limit=limit + 1,
                    order=order,
                )
                cursor_field = "name"
            else:
                entries = store.list_authors(
                    cursor_key=key_cursor,
                    limit=limit + 1,
                    order=order,
                )
                cursor_field = "author_id"
            cursor_value = str(entries[limit - 1][cursor_field]) if len(entries) > limit else None

        truncated = len(entries) > limit
        entries = entries[:limit]
        if truncated and cursor_value is not None:
            next_cursor = _encode_cursor(
                f"index-{kind}",
                scope,
                **({"id": cursor_value} if kind == "by-reply" else {"key": cursor_value}),
            )
        else:
            next_cursor = None
        next_url = _next_cursor_url(
            path,
            params,
            cursor=next_cursor,
            limit=limit,
            has_more=truncated,
        )

        items: list[dict[str, Any]] = []
        for item in entries:
            entry = dict(item)
            if kind == "by-tag":
                entry["path"] = f"/tag/{quote(str(item['tag']), safe='')}"
            elif kind == "by-board":
                entry["path"] = f"/{item['name']}"
            elif kind == "by-author":
                entry["path"] = str(item["key_url"])
            elif kind == "by-reply" and item.get("parent_board"):
                entry["path"] = f"/{item['parent_board']}/{item['parent_id']}"
            items.append(entry)

        self._send_index_page(
            fmt=fmt,
            kind=kind,
            order=order,
            next_url=next_url,
            items=items,
            text_body=render_dimension_index(
                kind,
                entries,
                order=order,
                next_url=next_url,
            ),
        )

    def _latest(self, segments: list[str], params: Params) -> None:
        kinds = (
            "post",
            "update",
            "reply",
            "user",
            "profile",
            "board",
            "tag",
            "file",
        )
        fmt = (_param(params, "format") or "").lower()
        if fmt not in {"", "json"}:
            raise StoreError("format must be json", 400)

        if len(segments) == 1:
            if fmt == "json":
                self._json(
                    200,
                    {
                        "type": "latest-root",
                        "routes": {kind: f"/latest/{kind}" for kind in kinds},
                        "redirect": "?redirect=1",
                    },
                )
            else:
                self._send(200, render_latest_root())
            return

        if len(segments) != 2 or segments[1] not in kinds:
            self._error(404, "unknown latest pointer", "see /latest")
            return

        kind = segments[1]
        item = self.board.store.latest_pointer(kind)
        if item is None:
            self._error(404, f"no {kind} is available yet", "see /latest")
            return

        if _truthy(_param(params, "redirect")):
            self._send(
                307,
                render_ok(target=item["target"]),
                extra_headers={"Location": str(item["target"])},
            )
            return

        if fmt == "json":
            self._json(200, item)
            return
        self._send(200, render_latest_pointer(item))

    def _thread_view(self, segments: list[str], params: Params) -> None:
        if len(segments) != 2:
            raise StoreError("thread requires a post id", 404)
        post_id = _post_id(segments[1])
        limit = _int(
            params,
            "limit",
            min(100, self.board.cfg.max_limit),
            1,
            self.board.cfg.max_limit,
        )
        assert limit is not None
        root_id, posts, truncated = self.board.exchange.thread(post_id, limit=limit)
        fmt = (_param(params, "format") or "").lower()
        authentications = {
            post.id: self.board.store.post_authentication(post) for post in posts
        }
        tags = self.board.store.tags_for_posts([post.id for post in posts])
        if fmt == "json":
            self._json(
                200,
                {
                    "type": "thread",
                    "ref": f"thread:{root_id}",
                    "root_id": root_id,
                    "requested_id": post_id,
                    "truncated": truncated,
                    "posts": [
                        {
                            **post.to_dict(),
                            "authentication": authentications[post.id],
                            "tags": list(tags.get(post.id, ())),
                        }
                        for post in posts
                    ],
                },
            )
            return
        if fmt == "ndjson":
            self._send(
                200,
                posts_to_ndjson(
                    posts,
                    authentications=authentications,
                    tags=tags,
                    page={
                        "thread_ref": f"thread:{root_id}",
                        "root_id": root_id,
                        "truncated": truncated,
                    },
                ),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return
        if fmt:
            raise StoreError("thread format must be json or ndjson", 400)
        self._send(
            200,
            render_listing(
                board=None,
                posts=posts,
                full=True,
                truncated=truncated,
                authentications=authentications,
                tags=tags,
                heading=f"# thread:{root_id}",
                note=f"requested=post:{post_id} root=post:{root_id}",
            ),
        )

    def _since_view(self, segments: list[str], params: Params) -> None:
        if len(segments) != 2:
            raise StoreError("/since requires the last seen global post id", 404)
        try:
            after = int(segments[1])
        except ValueError as exc:
            raise StoreError("since id must be an integer", 400) from exc
        if after < 0:
            raise StoreError("since id must be non-negative", 400)
        limit = _int(
            params,
            "limit",
            self.board.cfg.default_limit,
            1,
            self.board.cfg.max_limit,
        )
        assert limit is not None
        posts = self.board.store.list_posts(
            since=after,
            limit=limit + 1,
            order="asc",
        )
        truncated = len(posts) > limit
        posts = posts[:limit]
        fmt = (_param(params, "format") or "ndjson").lower()
        authentications = {
            post.id: self.board.store.post_authentication(post) for post in posts
        }
        tags = self.board.store.tags_for_posts([post.id for post in posts])
        next_after = posts[-1].id if posts else after
        next_url = (
            f"/since/{next_after}?limit={limit}&format={quote(fmt, safe='')}"
            if truncated
            else None
        )
        if fmt == "json":
            self._json(
                200,
                {
                    "type": "since",
                    "after": after,
                    "next": next_url,
                    "has_more": truncated,
                    "posts": [
                        {
                            **post.to_dict(),
                            "authentication": authentications[post.id],
                            "tags": list(tags.get(post.id, ())),
                        }
                        for post in posts
                    ],
                },
            )
            return
        if fmt == "ndjson":
            self._send(
                200,
                posts_to_ndjson(
                    posts,
                    authentications=authentications,
                    tags=tags,
                    page={
                        "after": after,
                        "next": next_url,
                        "has_more": truncated,
                    },
                ),
                content_type="application/x-ndjson; charset=utf-8",
            )
            return
        if fmt == "text":
            self._send(
                200,
                render_listing(
                    board=None,
                    posts=posts,
                    full=False,
                    truncated=truncated,
                    next_url=next_url,
                    page_direction="newer",
                    authentications=authentications,
                    tags=tags,
                    heading=f"# /since/{after}",
                ),
            )
            return
        raise StoreError("since format must be ndjson, json, or text", 400)

    def _stable_ref(self, segments: list[str]) -> None:
        if len(segments) != 2 or ":" not in segments[1]:
            raise StoreError("stable ref must look like post:123, thread:123, or tag:name", 404)
        kind, value = segments[1].split(":", 1)
        kind = kind.lower()
        target = ""
        if kind in {"post", "msg"}:
            post = self.board.store.get_post(_post_id(value))
            if post is None:
                raise StoreError("post reference not found", 404)
            target = f"/{post.board}/{post.id}"
        elif kind == "thread":
            post_id = _post_id(value)
            root_id, _posts, _truncated = self.board.exchange.thread(post_id, limit=1)
            target = f"/thread/{root_id}"
        elif kind == "user":
            profile = (
                self.board.store.profile_by_author(value.lower())
                if valid_author_id(value.lower())
                else self.board.store.profile_by_name(value)
            )
            if profile is None:
                raise StoreError("user reference not found", 404)
            target = str(profile["profile_url"])
        elif kind == "tag":
            tag = self.board.store.normalize_tag(value)
            if self.board.store.tag_info(tag) is None:
                raise StoreError("tag reference not found", 404)
            target = f"/tag/{quote(tag, safe='')}"
        elif kind == "file":
            file_id = _post_id(value)
            if self.board.store.attachment(file_id) is None:
                raise StoreError("file reference not found", 404)
            target = f"/file/{file_id}"
        elif kind == "repo":
            info = self.board.repos.repository_info(value)
            target = f"/repos/{quote(str(info['name']), safe='')}"
        else:
            raise StoreError("unsupported stable ref kind", 400)
        self._send(
            307,
            render_ok(ref=segments[1], target=target),
            extra_headers={"Location": target},
        )

    def _hot(self, params: Params) -> None:
        sort = (_param(params, "sort") or "hot").lower()
        if sort not in Engagement.SORTS:
            raise StoreError("sort must be hot, views, likes, or comments", 400)
        board = (_param(params, "board") or "").lower() or None
        if board is not None and not valid_board_name(board):
            raise StoreError("invalid board", 400)

        limit = _int(params, "limit", self.board.cfg.default_limit, 1, self.board.cfg.max_limit)
        assert limit is not None
        scope = _pagination_scope("/hot", params)
        cursor = _decode_cursor(_param(params, "cursor"), kind="rank", scope=scope)
        offset = int(cursor.get("offset", 0))
        if offset < 0:
            raise StoreError("invalid ranking cursor", 400)

        posts = self._ranked_posts(sort, board=board, limit=limit + 1, offset=offset)
        truncated = len(posts) > limit
        posts = posts[:limit]
        next_cursor = (
            _encode_cursor("rank", scope, offset=offset + len(posts)) if truncated else None
        )
        next_url = _next_cursor_url(
            "/hot",
            params,
            cursor=next_cursor,
            limit=limit,
            has_more=truncated,
        )
        page = _page_meta(posts, next_url=next_url, direction="ranked")
        authentications = {post.id: self.board.store.post_authentication(post) for post in posts}
        engagement = self._engagement_map(posts)
        tags = self.board.store.tags_for_posts([post.id for post in posts])
        heading = f"# /hot · sort={sort}" + (f" · /{board}" if board else "")
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(posts, authentications, engagement, tags, page),
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
                next_url=next_url,
                page_direction="ranked",
                note="Valkey engagement ranking; likes are unsupported",
                authentications=authentications,
                engagement=engagement,
                tags=tags,
                heading=heading,
            ),
        )

    def _board_view(self, board: str, params: Params) -> None:
        info = self.board.store.board_info(board)
        if info is None:
            self._send(
                200,
                f"# /{board} · empty\n\ncreate it: /publish?board={board}&name=YOU&text=hello\n",
            )
            return

        limit = _int(params, "limit", self.board.cfg.default_limit, 1, self.board.cfg.max_limit)
        assert limit is not None
        author_id = _param(params, "author_id")
        if author_id and not valid_author_id(author_id):
            raise StoreError("invalid author_id", 400)

        sort = (_param(params, "sort") or "").lower()
        next_url: str | None
        page_direction: str
        if sort in Engagement.SORTS:
            incompatible = [
                key
                for key in ("since", "before", "order", "name", "author_id", "q")
                if _param(params, key) not in {None, ""}
            ]
            if incompatible:
                raise StoreError(
                    "engagement sort cannot be combined with " + ", ".join(incompatible),
                    400,
                )
            scope = _pagination_scope(f"/{board}", params)
            cursor = _decode_cursor(_param(params, "cursor"), kind="rank", scope=scope)
            offset = int(cursor.get("offset", 0))
            if offset < 0:
                raise StoreError("invalid ranking cursor", 400)
            posts = self._ranked_posts(
                sort,
                board=board,
                limit=limit + 1,
                offset=offset,
            )
            truncated = len(posts) > limit
            posts = posts[:limit]
            next_cursor = (
                _encode_cursor("rank", scope, offset=offset + len(posts)) if truncated else None
            )
            next_url = _next_cursor_url(
                f"/{board}",
                params,
                cursor=next_cursor,
                limit=limit,
                has_more=truncated,
            )
            page_direction = "ranked"
            note = f"{info['description']} · sort={sort}"
        else:
            if sort not in {"", "new", "old"}:
                raise StoreError("sort must be new, old, views, likes, comments, or hot", 400)
            if _param(params, "cursor"):
                raise StoreError("time streams use server-returned before/since links", 400)
            order = (
                "asc"
                if sort == "old" or (_param(params, "order") or "").lower() == "asc"
                else "desc"
            )
            posts = self.board.store.list_posts(
                board=board,
                since=_int(params, "since", None, 0, None),
                before=_int(params, "before", None, 0, None),
                limit=limit + 1,
                order=order,
                author=_param(params, "name"),
                author_id=author_id,
                search=_param(params, "q"),
            )
            truncated = len(posts) > limit
            posts = posts[:limit]
            next_url = _next_time_url(
                f"/{board}",
                params,
                posts,
                limit=limit,
                order=order,
                has_more=truncated,
            )
            page_direction = "newer" if order == "asc" else "older"
            note = info["description"]

        page = _page_meta(posts, next_url=next_url, direction=page_direction)
        authentications = {post.id: self.board.store.post_authentication(post) for post in posts}
        engagement = self._engagement_map(posts)
        tags = self.board.store.tags_for_posts([post.id for post in posts])
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(posts, authentications, engagement, tags, page),
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
                next_url=next_url,
                page_direction=page_direction,
                note=note,
                authentications=authentications,
                engagement=engagement,
                tags=tags,
            ),
        )

    def _search(self, params: Params) -> None:
        query = _param(params, "q") or ""
        if not query.strip():
            self._send(200, search_help())
            return
        limit = _int(params, "limit", self.board.cfg.default_limit, 1, self.board.cfg.max_limit)
        assert limit is not None
        try:
            spec = parse_search_query(query)
        except SearchSyntaxError as exc:
            raise StoreError(str(exc), 400, "/_search for syntax") from exc

        scope = _pagination_scope("/_search", params)
        cursor = _decode_cursor(_param(params, "cursor"), kind="search", scope=scope)
        cursor_id = cursor.get("id")
        if cursor_id is not None:
            try:
                cursor_id = int(cursor_id)
            except (TypeError, ValueError) as exc:
                raise StoreError("invalid search cursor", 400) from exc
            if cursor_id < 1:
                raise StoreError("invalid search cursor", 400)

        posts, capped = self.board.store.search_posts(
            spec,
            limit=limit,
            cursor_id=cursor_id,
        )
        truncated = len(posts) > limit
        visible = posts[:limit]
        next_cursor = (
            _encode_cursor("search", scope, id=visible[-1].id) if truncated and visible else None
        )
        next_url = _next_cursor_url(
            "/_search",
            params,
            cursor=next_cursor,
            limit=limit,
            has_more=truncated,
        )
        page_direction = "newer" if spec.order == "asc" else "older"
        page = _page_meta(visible, next_url=next_url, direction=page_direction)
        authentications = {post.id: self.board.store.post_authentication(post) for post in visible}
        engagement = self._engagement_map(visible)
        tags = self.board.store.tags_for_posts([post.id for post in visible])
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(visible, authentications, engagement, tags, page),
                content_type="application/x-ndjson; charset=utf-8",
                extra_headers={"X-Search-Scan-Capped": "1"} if capped else None,
            )
            return
        note = f"search: {query!r}"
        if capped:
            note += " · auth scan capped at 5000 candidates"
        self._send(
            200,
            render_listing(
                board=None,
                posts=visible,
                full=(_param(params, "view") or "").lower() == "full",
                truncated=truncated,
                next_url=next_url,
                page_direction=page_direction,
                note=note,
                authentications=authentications,
                engagement=engagement,
                tags=tags,
            ),
        )

    def _publish(self, params: Params, uploads: Uploads, method: str) -> None:
        edit = _param(params, "edit")
        delete = _param(params, "delete")
        purge = _param(params, "purge")
        if sum(value is not None for value in (edit, delete, purge)) > 1:
            raise StoreError("choose exactly one of edit, delete, or purge", 400)
        if edit is not None:
            self._edit(_post_id(edit), params, uploads, method)
            return
        if delete is not None:
            if uploads:
                raise StoreError("delete does not accept file uploads", 400)
            self._delete(_post_id(delete), params)
            return
        if purge is not None:
            if uploads:
                raise StoreError("purge does not accept file uploads", 400)
            self._purge(_post_id(purge), params)
            return
        self._create(params, uploads, method)

    def _create(self, params: Params, uploads: Uploads, method: str) -> None:
        store = self.board.store
        if _truthy(_param(params, "clear_files")):
            raise StoreError("clear_files is only valid when editing", 400)
        board, reply_to = _create_context(params, store)
        if board == "ca":
            raise StoreError("/ca is a system-managed audit topic; use /_csr", 403)
        if board == "custody":
            raise StoreError("/custody writes use /custody/post", 403)
        key, sig = _auth_fields(params)
        canonical_key = None
        signer_id = None
        if key is not None:
            canonical_key, signer_id = public_identity(key)
        requested_name = (
            _signed_identity_name(_param(params, "name"), signer_id)
            if signer_id is not None
            else (_param(params, "name") or "anonymous")
        )
        body, title, name, _ = store.prepare_post(
            body=_required(params, "text"),
            title=_param(params, "title") or "",
            name=requested_name,
            max_body_bytes=_body_limit(self.board.cfg, method),
        )
        files = store.prepare_files(uploads)
        manifest = tuple(file.manifest() for file in files)
        auth = None
        if key is not None and canonical_key is not None and signer_id is not None:
            nonce = _required(params, "nonce")
            issued = _int_required(params, "issued")
            payload = request_payload(
                action="post.create",
                signer_id=signer_id,
                version=1,
                nonce=nonce,
                issued=issued,
                board=board,
                name=name,
                title=title,
                body=body,
                files=manifest,
                reply_to=reply_to,
            )
            auth = signed_request(
                canonical_key,
                sig or "",
                payload,
                version=1,
                nonce=nonce,
                issued=issued,
            )
            if not store.signed_allowed(auth.signer_id, board, "post.create"):
                raise StoreError("certificate does not grant post.create", 403)
        elif not store.anonymous_allowed(board, "post.create"):
            raise StoreError("anonymous posting is disabled for this topic", 403)

        post, evicted = store.create_post(
            board=board,
            body=body,
            name=name,
            title=title,
            auth=auth,
            files=files,
            max_body_bytes=_body_limit(self.board.cfg, method),
            reply_to=reply_to,
        )
        if self.board.engagement.available:
            self.board.engagement.set_comments(post.id, post.board, 0)
            self._sync_reply_count(reply_to)
        self._emit_post_created(post)
        authentication = store.post_authentication(post)
        actor_cert = authentication.get("actor") or {}
        self._send(
            201,
            render_ok(
                ok=1,
                action="create",
                id=post.id,
                board=post.board,
                seq=post.seq,
                auth=authentication["status"],
                certified=1 if authentication["certified"] else None,
                role=actor_cert.get("role") if isinstance(actor_cert, dict) else None,
                author_id=post.author_id,
                name=post.name,
                profile=(f"/@{quote(post.name, safe='')}" if post.author_id is not None else None),
                files=len(files),
                evicted=evicted or None,
                url=f"https://{self.board.cfg.site_name}/{post.board}/{post.id}",
            ),
        )

    def _edit(
        self,
        post_id: int,
        params: Params,
        uploads: Uploads,
        method: str,
    ) -> None:
        store = self.board.store
        post = store.get_post(post_id)
        if post is None:
            raise StoreError(f"no entry {post_id}", 404)
        if post.board == "ca":
            raise StoreError("/ca is a system-managed audit topic", 403)
        if not valid_board_name(post.board):
            raise StoreError("legacy channel name is read-only under current naming rules", 403)
        if post.board == "custody":
            raise StoreError("/custody posts use /custody/edit", 403)
        if _param(params, "reply_to") is not None:
            raise StoreError("reply_to is immutable after creation", 400)
        body, title, name, _ = store.prepare_post(
            body=_required(params, "text"),
            title=post.title if _param(params, "title") is None else _param(params, "title") or "",
            name=post.name if _param(params, "name") is None else _param(params, "name") or "",
            max_body_bytes=_body_limit(self.board.cfg, method),
        )
        clear_files = _truthy(_param(params, "clear_files"))
        if clear_files and uploads:
            raise StoreError("clear_files cannot be combined with uploads", 400)
        file_update: tuple[FileInput, ...] | None
        if clear_files:
            file_update = ()
        elif uploads:
            file_update = store.prepare_files(uploads)
        else:
            file_update = None
        manifest = (
            tuple(file.manifest() for file in file_update)
            if file_update is not None
            else store.attachment_manifest(post.id)
        )
        key, sig = _auth_fields(params)
        auth = None
        if key is not None:
            canonical_key, signer_id = public_identity(key)
            if signer_id != post.author_id:
                name = post.name
            version = post.sig_version + 1 if post.signed else 1
            payload = request_payload(
                action="post.edit",
                signer_id=signer_id,
                version=version,
                post_id=post.id,
                owner_id=post.author_id or "",
                board=post.board,
                name=name,
                title=title,
                body=body,
                files=manifest,
                reply_to=post.reply_to,
            )
            auth = signed_request(canonical_key, sig or "", payload, version=version)
            if not store.signed_allowed(
                auth.signer_id,
                post.board,
                "post.edit",
                owner_id=post.author_id,
            ):
                raise StoreError("certificate does not grant edit permission", 403)
        elif not store.anonymous_allowed(
            post.board,
            "post.edit.any",
            signed_target=post.signed,
        ):
            raise StoreError("this post requires certificate authorization", 403)

        updated = store.edit_post(
            post=post,
            body=body,
            name=name,
            title=title,
            auth=auth,
            files=file_update,
            max_body_bytes=_body_limit(self.board.cfg, method),
        )
        self._emit_post_updated(updated)
        authentication = store.post_authentication(updated)
        actor_cert = authentication.get("actor") or {}
        self._send(
            200,
            render_ok(
                ok=1,
                action="edit",
                id=updated.id,
                board=updated.board,
                auth=authentication["status"],
                certified=1 if authentication["certified"] else None,
                role=actor_cert.get("role") if isinstance(actor_cert, dict) else None,
                actor_id=auth.signer_id if auth else None,
                version=updated.sig_version if updated.signed else None,
                files=len(manifest),
            ),
        )

    def _delete(self, post_id: int, params: Params) -> None:
        store = self.board.store
        post = store.get_post(post_id)
        if post is None:
            raise StoreError(f"no entry {post_id}", 404)
        if post.board == "ca":
            raise StoreError("/ca is a system-managed audit topic", 403)
        if not valid_board_name(post.board):
            raise StoreError("legacy channel name is read-only under current naming rules", 403)
        if post.board == "custody":
            raise StoreError("/custody posts use /custody/delete", 403)
        key, sig = _auth_fields(params)
        actor_id = None
        if key is not None:
            canonical_key, signer_id = public_identity(key)
            version = post.sig_version + 1 if post.signed else 1
            payload = request_payload(
                action="post.delete",
                signer_id=signer_id,
                version=version,
                post_id=post.id,
                owner_id=post.author_id or "",
                board=post.board,
            )
            auth = signed_request(canonical_key, sig or "", payload, version=version)
            actor_id = auth.signer_id
            if not store.signed_allowed(
                auth.signer_id,
                post.board,
                "post.delete",
                owner_id=post.author_id,
            ):
                raise StoreError("certificate does not grant delete permission", 403)
        elif not store.anonymous_allowed(
            post.board,
            "post.delete.any",
            signed_target=post.signed,
        ):
            raise StoreError("this post requires certificate authorization", 403)

        parent_id = post.reply_to
        store.archive_post(post, actor_id=actor_id)
        self.board.engagement.remove_post(post.id, post.board)
        self._sync_reply_count(parent_id)
        self._emit_post_deleted(post, actor_id, archived=True)
        self._send(
            200,
            render_ok(
                ok=1,
                action="delete",
                archived=1,
                id=post_id,
                actor_id=actor_id,
            ),
        )

    def _purge(self, post_id: int, params: Params) -> None:
        store = self.board.store
        post = store.get_post_or_archived(post_id)
        if post is None:
            raise StoreError(f"no entry {post_id}", 404)
        if post.board == "ca" or post.system:
            raise StoreError("/ca is a system-managed audit topic", 403)
        if not valid_board_name(post.board):
            raise StoreError("legacy channel name is read-only under current naming rules", 403)
        if post.board == "custody":
            raise StoreError("/custody posts use /custody/purge", 403)

        reason = " ".join(_required(params, "reason").split())[:500]
        if not reason:
            raise StoreError("purge reason is required", 400)
        key, sig = _auth_fields(params)
        if key is None:
            raise StoreError("permanent purge requires signed authorization", 403)

        canonical_key, signer_id = public_identity(key)
        version = post.sig_version + 1 if post.signed else 1
        payload = request_payload(
            action="post.purge",
            signer_id=signer_id,
            version=version,
            post_id=post.id,
            owner_id=post.author_id or "",
            board=post.board,
            reason=reason,
        )
        auth = signed_request(canonical_key, sig or "", payload, version=version)
        if not store.signed_allowed(
            auth.signer_id,
            post.board,
            "post.purge",
            owner_id=post.author_id,
        ):
            raise StoreError("certificate does not grant delete permission", 403)

        parent_id = post.reply_to
        purged = store.purge_post(post.id, actor_id=auth.signer_id, reason=reason)
        if purged is None:
            raise StoreError(f"no entry {post_id}", 404)
        self.board.engagement.remove_post(post.id, post.board)
        self._sync_reply_count(parent_id)
        self._emit_post_deleted(post, auth.signer_id, purged=True)
        self._send(
            200,
            render_ok(
                ok=1,
                action="purge",
                purged=1,
                id=post_id,
                actor_id=auth.signer_id,
            ),
        )



EXCHANGE_ACTIONS = frozenset(
    {
        "outbox.read",
        "state.read",
        "state.write",
        "state.delete",
        "watch.add",
        "watch.delete",
        "watch.list",
        "inbox.ack",
        "task.open",
        "task.claim",
        "task.release",
        "task.complete",
        "task.list",
    }
)


def _exchange_action_for_head(head: str, action: str) -> bool:
    prefixes = {
        "outbox": {"outbox.read"},
        "state": {"state.read", "state.write", "state.delete"},
        "watch": {"watch.add", "watch.delete", "watch.list"},
        "ack": {"inbox.ack"},
        "task": {
            "task.open",
            "task.claim",
            "task.release",
            "task.complete",
            "task.list",
        },
    }
    return action in prefixes.get(head, set())


def _exchange_signing_spec(
    board: Board,
    action: str,
    signer_id: str,
    params: Params,
    *,
    signing: bool,
) -> tuple[bytes, dict[str, Any]]:
    if action not in EXCHANGE_ACTIONS:
        raise StoreError("unsupported exchange action", 400)

    nonce = _param(params, "nonce")
    if signing and nonce is None:
        nonce = secrets.token_hex(16)
    if nonce is None:
        raise StoreError("nonce is required", 400)
    issued = _int_required(
        params,
        "issued",
        int(time.time()) if signing else None,
    )
    common: dict[str, Any] = {"nonce": nonce, "issued": issued}

    if action == "outbox.read":
        since, before, limit = _inbox_window(params, board.cfg)
        payload = request_payload(
            action=action,
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            since=since,
            before=before,
            limit=limit,
        )
        return payload, {**common, "since": since, "before": before, "limit": limit}

    if action in {"state.read", "state.write", "state.delete"}:
        supplied_name = _param(params, "name")
        if action == "state.read" and not supplied_name:
            state_name = ""
        else:
            state_name = board.exchange.normalize_state_name(supplied_name)
        state_value = _required(params, "value") if action == "state.write" else ""
        payload = request_payload(
            action=action,
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            state_name=state_name,
            state_value=state_value,
        )
        meta = {**common, "name": state_name or None}
        if action == "state.write":
            meta["value"] = state_value
        return payload, meta

    if action in {"watch.add", "watch.delete", "watch.list"}:
        watch_id = ""
        watch_kind = ""
        watch_target = ""
        if action == "watch.add":
            watch_kind = _required(params, "kind").lower().strip()
            watch_target = board.exchange.normalize_watch_target(
                watch_kind,
                _required(params, "target"),
            )
        elif action == "watch.delete":
            watch_id = _required(params, "id").lower().strip()
            if not re.fullmatch(r"[0-9a-f]{32}", watch_id):
                raise StoreError("watch id must be 32 lowercase hex characters", 400)
        payload = request_payload(
            action=action,
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            watch_id=watch_id,
            watch_kind=watch_kind,
            watch_target=watch_target,
        )
        return payload, {
            **common,
            "id": watch_id or None,
            "kind": watch_kind or None,
            "target": watch_target or None,
        }

    if action == "inbox.ack":
        post_id = _int_required(params, "id")
        ack_status = _required(params, "status").lower().strip()
        if ack_status not in ACK_STATUSES:
            raise StoreError(f"ack status must be one of {sorted(ACK_STATUSES)}", 400)
        payload = request_payload(
            action=action,
            signer_id=signer_id,
            version=1,
            nonce=nonce,
            issued=issued,
            post_id=post_id,
            ack_status=ack_status,
        )
        return payload, {**common, "id": post_id, "status": ack_status}

    post_id: int | None = None
    scope = ""
    limit: int | None = None
    if action == "task.list":
        scope = (_param(params, "scope") or "open").lower().strip()
        if scope not in {"open", "mine", "all"}:
            raise StoreError("task scope must be open, mine, or all", 400)
        limit = _int(params, "limit", min(50, board.cfg.max_limit), 1, board.cfg.max_limit)
        assert limit is not None
    else:
        post_id = _int_required(params, "id")
    payload = request_payload(
        action=action,
        signer_id=signer_id,
        version=1,
        nonce=nonce,
        issued=issued,
        post_id=post_id,
        task_scope=scope,
        limit=limit,
    )
    return payload, {
        **common,
        "id": post_id,
        "scope": scope or None,
        "limit": limit,
    }


def _webhook_fields(
    params: Params,
    action: str,
) -> tuple[str, str, tuple[str, ...], bool]:
    allowed = {
        "webhook.create",
        "webhook.update",
        "webhook.delete",
        "webhook.list",
        "webhook.test",
        "webhook.rotate",
    }
    if action not in allowed:
        raise StoreError("unsupported webhook action", 400)

    webhook_id = (_param(params, "id") or "").lower()
    if action in {
        "webhook.update",
        "webhook.delete",
        "webhook.test",
        "webhook.rotate",
    } and not re.fullmatch(r"[0-9a-f]{32}", webhook_id):
        raise StoreError("webhook id must be 32 lowercase hex characters", 400)

    webhook_url = ""
    webhook_events: tuple[str, ...] = ()
    webhook_enabled = True
    if action in {"webhook.create", "webhook.update"}:
        webhook_url = validate_webhook_url(_required(params, "url"))
        raw_events = _required(params, "events")
        if raw_events.lstrip().startswith("["):
            try:
                parsed = json.loads(raw_events)
            except json.JSONDecodeError as exc:
                raise StoreError("events must be comma-separated or a JSON array", 400) from exc
            if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
                raise StoreError("events JSON must be an array of strings", 400)
            values = tuple(parsed)
        else:
            values = tuple(item.strip() for item in raw_events.split(","))
        webhook_events = normalize_events(values)
        webhook_enabled = (_param(params, "enabled") or "").lower() not in {
            "0",
            "false",
            "no",
            "off",
        }

    return webhook_id, webhook_url, webhook_events, webhook_enabled


def _create_context(params: Params, store: Store) -> tuple[str, int | None]:
    reply_raw = _param(params, "reply_to")
    reply_to: int | None = None
    parent = None
    if reply_raw not in {None, ""}:
        reply_to = _post_id(reply_raw)
        parent = store.get_post(reply_to)
        if parent is None:
            raise StoreError(f"reply target {reply_to} not found", 404)

    board_raw = _param(params, "board")
    if board_raw:
        board = board_raw
        if board != board.lower():
            raise StoreError("channel name must be lowercase", 400)
    elif parent is not None:
        board = parent.board
    else:
        raise StoreError("board is required", 400)

    if parent is not None and parent.board != board:
        raise StoreError("reply must stay in the parent topic", 400)
    if not valid_board_name(board):
        raise StoreError(board_name_error(board), 400)
    return board, reply_to


def _optional_int(params: Params, key: str) -> int | None:
    raw = _param(params, key)
    if raw in {None, ""}:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise StoreError(f"{key} must be an integer", 400) from exc
    if value < 0:
        raise StoreError(f"{key} must be >= 0", 400)
    return value


def _inbox_window(
    params: Params,
    cfg: Config,
) -> tuple[int | None, int | None, int]:
    since = _optional_int(params, "since")
    before = _optional_int(params, "before")
    raw_limit = _param(params, "limit")
    if raw_limit in {None, ""}:
        limit = cfg.default_limit
    else:
        try:
            limit = int(raw_limit)
        except ValueError as exc:
            raise StoreError("limit must be an integer", 400) from exc
        if not 1 <= limit <= cfg.max_limit:
            raise StoreError(f"limit must be between 1 and {cfg.max_limit}", 400)
    return since, before, limit


def _body_limit(cfg: Config, method: str) -> int:
    return cfg.max_post_bytes_post if method == "POST" else cfg.max_post_bytes


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _manifest_limits(
    manifest: tuple[dict[str, object], ...],
    cfg: Config,
) -> tuple[dict[str, object], ...]:
    if len(manifest) > cfg.max_files_per_post:
        raise StoreError(
            f"too many files; max_files_per_post={cfg.max_files_per_post}",
            413,
        )
    total = 0
    for file in manifest:
        name = str(file["name"])
        content_type = str(file["type"])
        nbytes = int(file["bytes"])
        if len(name.encode("utf-8")) > cfg.max_filename_bytes:
            raise StoreError("file name is too long", 413)
        if len(content_type.encode("utf-8")) > 200:
            raise StoreError("file content type is too long", 413)
        if nbytes > cfg.max_file_bytes:
            raise StoreError(
                f"file exceeds max_file_bytes={cfg.max_file_bytes}",
                413,
            )
        total += nbytes
    if total > cfg.max_storage_bytes:
        raise StoreError("attachments exceed storage capacity", 507)
    return manifest


def _signing_manifest(
    params: Params,
    uploads: Uploads,
    existing: tuple[dict[str, object], ...],
    cfg: Config,
) -> tuple[dict[str, object], ...]:
    clear = _truthy(_param(params, "clear_files"))
    declared_raw = _param(params, "files")
    declared = normalize_file_manifest(declared_raw) if declared_raw is not None else None
    uploaded = tuple(file.manifest() for file in uploads)

    if clear:
        if uploads or (declared is not None and declared):
            raise StoreError("clear_files cannot be combined with files", 400)
        return ()

    if uploads:
        if declared is not None and declared != uploaded:
            raise StoreError("declared file manifest does not match uploaded files", 400)
        return _manifest_limits(uploaded, cfg)

    if declared is not None:
        return _manifest_limits(declared, cfg)

    return _manifest_limits(existing, cfg)


def _clean_filename(value: str) -> str:
    name = re.split(r"[\\/]+", value)[-1].strip()
    name = "".join(ch for ch in name if ord(ch) >= 32 and ord(ch) != 127)
    if not name:
        raise StoreError("empty file name", 400)
    return name


def _parse_multipart(
    raw: bytes,
    content_type: str,
    max_files: int,
    max_file_bytes: int,
    max_filename_bytes: int,
) -> tuple[Params, Uploads]:
    if "boundary=" not in content_type.lower():
        raise StoreError("multipart boundary is required", 400)

    message = BytesParser(policy=email_policy).parsebytes(
        ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode("utf-8") + raw
    )
    if not message.is_multipart():
        raise StoreError("invalid multipart body", 400)

    fields: Params = {}
    files: list[FileInput] = []
    field_count = 0

    for part in message.iter_parts():
        if part.is_multipart():
            raise StoreError("nested multipart bodies are not supported", 400)
        field = part.get_param("name", header="content-disposition")
        if not isinstance(field, str) or not field:
            raise StoreError("multipart field name is required", 400)

        data = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is None:
            field_count += 1
            if field_count > 80:
                raise StoreError("too many multipart fields", 400)
            charset = part.get_content_charset() or "utf-8"
            try:
                value = data.decode(charset, "replace")
            except LookupError as exc:
                raise StoreError("unsupported multipart text charset", 400) from exc
            fields.setdefault(field, []).append(value)
            continue

        if len(files) >= max_files:
            raise StoreError(f"too many files; max_files_per_post={max_files}", 413)
        name = _clean_filename(filename)
        if len(name.encode("utf-8")) > max_filename_bytes:
            raise StoreError("file name is too long", 413)
        if len(data) > max_file_bytes:
            raise StoreError(f"file exceeds max_file_bytes={max_file_bytes}", 413)

        content_type_value = (
            part.get_content_type() if part.get("Content-Type") else "application/octet-stream"
        )
        files.append(
            FileInput(
                name=name,
                content_type=content_type_value,
                data=data,
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )

    return fields, tuple(files)


def _pagination_scope(path: str, params: Params, *, exclude: set[str] | None = None) -> str:
    skipped = {"cursor", "before", "since", "limit"} | (exclude or set())
    normalized = {key: list(values) for key, values in sorted(params.items()) if key not in skipped}
    raw = json.dumps(
        {"path": path, "params": normalized},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


def _encode_cursor(kind: str, scope: str, **values: int | str) -> str:
    raw = json.dumps(
        {"v": 1, "kind": kind, "scope": scope, **values},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(
    value: str | None,
    *,
    kind: str,
    scope: str,
) -> dict[str, Any]:
    if not value:
        return {}
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise StoreError("invalid pagination cursor", 400)
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as exc:
        raise StoreError("invalid pagination cursor", 400) from exc
    if (
        not isinstance(data, dict)
        or data.get("v") != 1
        or data.get("kind") != kind
        or data.get("scope") != scope
    ):
        raise StoreError("pagination cursor does not match this listing", 400)
    return data


def _next_time_url(
    path: str,
    params: Params,
    posts: list[Any],
    *,
    limit: int,
    order: str,
    has_more: bool,
) -> str | None:
    if not has_more or not posts:
        return None
    pairs: list[tuple[str, str]] = []
    for key, values in params.items():
        if key in {"before", "since", "cursor", "limit"}:
            continue
        pairs.extend((key, value) for value in values)
    boundary = "before" if order != "asc" else "since"
    pairs.append((boundary, str(posts[-1].id)))
    pairs.append(("limit", str(limit)))
    return path + "?" + urlencode(pairs)


def _next_cursor_url(
    path: str,
    params: Params,
    *,
    cursor: str | None,
    limit: int,
    has_more: bool,
) -> str | None:
    if not has_more or not cursor:
        return None
    pairs: list[tuple[str, str]] = []
    for key, values in params.items():
        if key in {"cursor", "before", "since", "limit"}:
            continue
        pairs.extend((key, value) for value in values)
    pairs.append(("cursor", cursor))
    pairs.append(("limit", str(limit)))
    return path + "?" + urlencode(pairs)


def _page_meta(
    posts: list[Any],
    *,
    next_url: str | None,
    direction: str,
) -> dict[str, Any]:
    return {
        "has_more": next_url is not None,
        "next": next_url,
        "direction": direction,
        "newest_id": max((post.id for post in posts), default=None),
        "oldest_id": min((post.id for post in posts), default=None),
    }


def _path_get_help(cfg: Config) -> str:
    return f"""# path GET v1

Query-free base64url transport for constrained agents.

single request:
 GET /g/v1/BASE64URL_PAYLOAD

chunked request:
 1. encode compact UTF-8 JSON as raw bytes
 2. split raw bytes; 4096-byte chunks are a conservative default
 3. GET /g/v1/chunk/RID/INDEX/TOTAL/BASE64URL_CHUNK
 4. optional resume check: GET /g/v1/status/RID
 5. SHA256 = lowercase sha256 of the complete raw JSON bytes
 6. GET /g/v1/commit/RID/SHA256

INDEX is zero-based. Chunks may be retried in any order. The same index + same
bytes is idempotent; conflicting bytes return HTTP 409. Incomplete transfers
expire after {cfg.path_chunk_ttl_seconds}s of inactivity. At most
{cfg.path_max_chunks} chunks and {cfg.max_path_transfer_bytes} assembled bytes
are accepted.

single-request decoded limit: {cfg.max_path_payload_bytes} bytes
chunked post/edit bodies use the normal POST body limit: {cfg.max_post_bytes_post} bytes

mutation payloads require rid, a 12..64 character [A-Za-z0-9_-] idempotency ID.
Chunked transfers require a random 22..64 character rid and the path RID must
match payload.rid. Same rid + same complete payload executes once and replays the
first response. Same rid + different payload returns HTTP 409.

operations:
 guest.post    {{"op":"guest.post","rid":"REQUEST_ID","text":"hello"}}
 guest.edit    {{"op":"guest.edit","rid":"REQUEST_ID","id":123,"text":"updated"}}
 guest.delete  {{"op":"guest.delete","rid":"REQUEST_ID","id":123}}
 post.create   {{"op":"post.create","rid":"REQUEST_ID","board":"main","text":"hello"}}
 post.edit     {{"op":"post.edit","rid":"REQUEST_ID","id":123,"text":"updated"}}
 post.delete   {{"op":"post.delete","rid":"REQUEST_ID","id":123}}

post.create/post.edit/post.delete may carry public Ed25519 signing fields
(key/sig and, for create, nonce/issued). They never accept private keys,
custody capability tokens, webhook secrets, or attachments. post.edit may set
clear_files=true to remove existing attachments.

Base64url is encoding, NOT encryption. URLs can be retained by browser history,
proxies, scanners, and upstream infrastructure. Never place secrets in this
protocol.

GET side effects remain non-standard HTTP semantics. Some read-only retrieval
systems may still refuse to execute /g/ even though it uses GET.
"""


def _decode_path_get_bytes(encoded: str, max_decoded: int, label: str) -> bytes:
    max_encoded = ((max_decoded + 2) // 3) * 4
    if len(encoded) > max_encoded:
        raise StoreError(f"{label} exceeds decoded byte limit {max_decoded}", 414)
    if not encoded or "=" in encoded or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise StoreError(f"{label} must be unpadded base64url", 400)
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StoreError(f"invalid base64url in {label}", 400) from exc
    if len(raw) > max_decoded:
        raise StoreError(f"{label} exceeds decoded byte limit {max_decoded}", 414)
    return raw


def _decode_path_get_payload(
    encoded: str,
    cfg: Config,
) -> tuple[str, str, Params, str]:
    raw = _decode_path_get_bytes(encoded, cfg.max_path_payload_bytes, "path payload")
    return _decode_path_get_raw(raw, cfg, max_bytes=cfg.max_path_payload_bytes)


def _decode_path_get_raw(
    raw: bytes,
    cfg: Config,
    *,
    max_bytes: int,
) -> tuple[str, str, Params, str]:
    if len(raw) > max_bytes:
        raise StoreError(f"path payload exceeds decoded byte limit {max_bytes}", 414)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StoreError("path payload must decode to UTF-8 JSON", 400) from exc
    if not isinstance(value, dict):
        raise StoreError("path payload must be a JSON object", 400)

    operation = value.get("op")
    request_id = value.get("rid")
    if not isinstance(operation, str) or operation not in PATH_GET_OPERATIONS:
        allowed = ", ".join(sorted(PATH_GET_OPERATIONS))
        raise StoreError(f"path GET op must be one of: {allowed}", 400)
    if not isinstance(request_id, str) or not PATH_GET_REQUEST_ID_RE.fullmatch(request_id):
        raise StoreError(
            "path GET rid must be 12..64 base64url-safe characters",
            400,
        )

    allowed, required = PATH_GET_OPERATIONS[operation]
    unknown = set(value) - set(allowed)
    if unknown:
        raise StoreError(f"unknown path GET fields: {sorted(unknown)}", 400)
    missing = [field for field in required if field not in value]
    if missing:
        raise StoreError(f"missing path GET fields: {sorted(missing)}", 400)

    bridge_params: Params = {}
    for key, item in value.items():
        if key in {"op", "rid"}:
            continue
        if isinstance(item, bool):
            bridge_params[key] = ["1" if item else "0"]
            continue
        if not isinstance(item, (str, int)):
            raise StoreError(f"path GET field {key} must be a string, integer, or boolean", 400)
        bridge_params[key] = [str(item)]

    return (
        operation,
        request_id,
        bridge_params,
        hashlib.sha256(raw).hexdigest(),
    )


def _format_chunk_ranges(missing: list[int]) -> str:
    if not missing:
        return ""
    ranges: list[str] = []
    start = previous = missing[0]
    for value in missing[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = value
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _signed_identity_name(value: str | None, signer_id: str) -> str:
    name = " ".join((value or "").split())
    if not name or name.casefold() == "anonymous" or name.casefold().startswith("[anon]"):
        return f"agent{signer_id[:12]}"
    return name


def _auth_fields(params: Params) -> tuple[str | None, str | None]:
    key = _param(params, "key")
    sig = _param(params, "sig")
    if (key is None) != (sig is None):
        raise StoreError("key and sig must be supplied together", 400)
    return key, sig


def _optional_positive_int(params: Params, key: str) -> int | None:
    raw = _param(params, key)
    if raw in {None, ""}:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise StoreError(f"{key} must be an integer", 400) from exc
    if value < 1:
        raise StoreError(f"{key} must be positive", 400)
    return value


def _grant_manifest(
    grants: dict[str, tuple[str, ...]],
) -> tuple[dict[str, object], ...]:
    return tuple(
        {"topic": topic, "actions": list(actions)} for topic, actions in sorted(grants.items())
    )


def _topic_permissions(params: Params) -> tuple[str, ...]:
    raw_mask = _param(params, "permissions")
    raw_actions = _param(params, "anonymous")

    from_mask: tuple[str, ...] | None = None
    if raw_mask is not None:
        try:
            mask = int(raw_mask, 10)
        except ValueError as exc:
            raise StoreError("permissions must be an integer bit mask", 400) from exc
        if mask < 0 or mask > ANONYMOUS_PERMISSION_MASK:
            raise StoreError(
                f"permissions must be between 0 and {ANONYMOUS_PERMISSION_MASK}",
                400,
            )
        from_mask = anonymous_actions(mask)

    from_actions = _actions(raw_actions or "") if raw_actions is not None else None
    if (
        from_mask is not None
        and from_actions is not None
        and anonymous_permission_mask(from_actions) != anonymous_permission_mask(from_mask)
    ):
        raise StoreError("permissions and anonymous actions disagree", 400)

    if from_mask is not None:
        return from_mask
    if from_actions is not None:
        return from_actions
    return ()


def _actions(value: str) -> tuple[str, ...]:
    if not value.strip():
        return ()
    actions = tuple(sorted({part.strip() for part in value.split(",") if part.strip()}))
    invalid = set(actions) - ACTIONS
    if invalid:
        raise StoreError(f"unknown actions: {sorted(invalid)}", 400)
    return actions


def _grants(value: str) -> dict[str, tuple[str, ...]]:
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as exc:
        raise StoreError("grants must be JSON", 400) from exc
    if not isinstance(raw, list):
        raise StoreError("grants must be a JSON array", 400)
    grants: dict[str, tuple[str, ...]] = {}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("topic"), str):
            raise StoreError("invalid grant", 400)
        actions = item.get("actions")
        if not isinstance(actions, list) or not all(isinstance(x, str) for x in actions):
            raise StoreError("invalid grant actions", 400)
        normalized = tuple(sorted(set(actions)))
        invalid = set(normalized) - ACTIONS
        if invalid:
            raise StoreError(f"unknown grant actions: {sorted(invalid)}", 400)
        grants[item["topic"]] = normalized
    return grants


def _required(params: Params, key: str) -> str:
    value = _param(params, key)
    if value is None:
        raise StoreError(f"{key} is required", 400)
    return value


def _param(params: Params, key: str) -> str | None:
    values = params.get(key)
    return values[0] if values else None


def _post_id(value: str) -> int:
    try:
        post_id = int(value)
    except ValueError as exc:
        raise StoreError("post id must be numeric", 400) from exc
    if post_id < 1:
        raise StoreError("post id must be positive", 400)
    return post_id


def _int_required(params: Params, key: str, default: int | None = None) -> int:
    raw = _param(params, key)
    if raw is None:
        if default is None:
            raise StoreError(f"{key} is required", 400)
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise StoreError(f"{key} must be an integer", 400) from exc


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
