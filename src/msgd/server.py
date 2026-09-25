"""HTTP server for msgd."""

from __future__ import annotations

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
from urllib.parse import parse_qs, quote, unquote, urlparse

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
from msgd.ratelimit import Limiter
from msgd.render import (
    posts_to_ndjson,
    render_agent_index,
    render_error,
    render_inbox,
    render_index,
    render_listing,
    render_ok,
    render_post,
    render_rules,
    render_schema,
    render_sitemap,
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
    valid_author_id,
    valid_board_name,
)

Params = dict[str, list[str]]
Uploads = tuple[FileInput, ...]


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
        self.engagement = Engagement(cfg.valkey_url, prefix=cfg.valkey_prefix)
        if cfg.valkey_required and not self.engagement.available:
            raise RuntimeError(
                f"Valkey analytics is required but unavailable: {self.engagement.error}"
            )
        if self.engagement.available:
            self.engagement.sync_comments(self.store.comment_counts())
        self.reads = Limiter(
            burst=max(30, cfg.read_per_minute // 4),
            per_minute=cfg.read_per_minute,
        )
        self.writes = Limiter(burst=cfg.write_burst, per_minute=cfg.write_per_minute)
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
        self.board.engagement.close()
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
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Access-Control-Allow-Origin", self.board.cfg.cors_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Link", '</rules>; rel="help"')
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

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
    ) -> list[Any]:
        if not self.board.engagement.available:
            raise StoreError("Valkey analytics is unavailable", 503)
        scan = min(max(limit * 5, 100), 5000)
        ids = self.board.engagement.rank(metric, board=board, limit=scan)
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
                "Disallow: /custody/delete\n\n"
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
        if head == "favicon.ico":
            self._send(204, b"")
            return

        if uploads and head not in {"publish", "_signing"}:
            raise StoreError("file uploads are only accepted by /publish or /_signing", 400)

        if head in {"publish", "_cert", "_csr", "_revoke", "_policy"} and method == "HEAD":
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

        if head == "publish":
            if self._limited(True):
                return
            self._publish(params, uploads, method)
            return

        if self._limited(False):
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
                ),
            )
            return
        if head == "index" and len(segments) == 1 and _param(params, "format") is None:
            store = self.board.store
            recent = [post for post in store.list_posts(limit=8) if post.board != "index"][:6]
            hot = (
                self._ranked_posts("hot", board=None, limit=6)
                if self.board.engagement.available
                else []
            )
            visible = list({post.id: post for post in [*recent, *hot]}.values())
            self._send(
                200,
                render_agent_index(
                    self.board.cfg,
                    store.list_boards(),
                    store.stats(),
                    recent=recent,
                    hot=hot,
                    authentications={post.id: store.post_authentication(post) for post in visible},
                    engagement=self._engagement_map(visible),
                ),
            )
            return
        if head == "hot":
            self._hot(params)
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

        if not valid_board_name(head):
            hint = f"{head!r} is reserved" if head in RESERVED_BOARDS else "invalid board name"
            self._error(404, f"no such board: {head}", hint)
            return

        if len(segments) == 1:
            self._board_view(head, params)
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
                    "likes": "unsupported",
                    "files": [file.to_dict() for file in self.board.store.attachments(post.id)],
                },
            )
        else:
            self._error(404, f"unknown action: {action}", "try /raw or /meta")

    def _signing(self, params: Params, uploads: Uploads, method: str) -> None:
        action = _param(params, "action") or ""
        if uploads and action not in {"post.create", "post.edit"}:
            raise StoreError("file uploads are only valid for post.create/post.edit signing", 400)
        key = _required(params, "key")
        _, signer_id = public_identity(key)
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
                name=_param(params, "name") or "anonymous",
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

        if action in {"post.edit", "post.delete"}:
            post = store.get_post(_int_required(params, "id"))
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
                    if _param(params, "name") is None
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
                payload = request_payload(
                    action=action,
                    signer_id=signer_id,
                    version=version,
                    post_id=post.id,
                    owner_id=post.author_id or "",
                    board=post.board,
                )
            response = {"signer_id": signer_id, "version": version, **payload_info(payload)}
            if action == "post.edit":
                response["files"] = list(manifest)
            self._json(200, response)
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
            board = (_required(params, "board")).lower()
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
        self.board.store.revoke_certificate(serial, auth.signer_id, reason)
        self._send(200, render_ok(ok=1, action="revoke", serial=serial, by=auth.signer_id))

    def _policy(self, params: Params) -> None:
        board = (_required(params, "board")).lower()
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
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            lines = []
            for post, kinds in events:
                lines.append(
                    json.dumps(
                        {
                            "kinds": list(kinds),
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
            ),
        )

    def _guest_bridge(self, action: str, params: Params) -> None:
        if action == "post":
            self._create({**params, "board": ["guest"]}, (), "GET")
            return
        post_id = _post_id(_required(params, "id"))
        post = self.board.store.get_post(post_id)
        if post is None or post.board != "guest":
            raise StoreError("guest post not found", 404)
        if action == "edit":
            self._edit(post_id, params, (), "GET")
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
        post = store.get_post(post_id)
        if post is None or post.board != "custody":
            raise StoreError("custody post not found", 404)
        if not store.custody_owns(token, post):
            raise StoreError("custody token does not own this post", 403)

        if action == "delete":
            parent_id = post.reply_to
            store.delete_post(post)
            self.board.engagement.remove_post(post.id, post.board)
            self._sync_reply_count(parent_id)
            self._send(200, render_ok(ok=1, action="delete", id=post_id, auth="custodial"))
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

    def _hot(self, params: Params) -> None:
        sort = (_param(params, "sort") or "hot").lower()
        if sort not in Engagement.SORTS:
            raise StoreError("sort must be hot, views, or comments", 400)
        board = (_param(params, "board") or "").lower() or None
        if board is not None and not valid_board_name(board):
            raise StoreError("invalid board", 400)

        limit = _int(params, "limit", self.board.cfg.default_limit, 1, self.board.cfg.max_limit)
        assert limit is not None
        posts = self._ranked_posts(sort, board=board, limit=limit + 1)
        truncated = len(posts) > limit
        posts = posts[:limit]
        authentications = {post.id: self.board.store.post_authentication(post) for post in posts}
        engagement = self._engagement_map(posts)
        heading = f"# /hot · sort={sort}" + (f" · /{board}" if board else "")
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(posts, authentications, engagement),
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
                note="Valkey engagement ranking; likes are unsupported",
                authentications=authentications,
                engagement=engagement,
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
            posts = self._ranked_posts(sort, board=board, limit=limit + 1)
            note = f"{info['description']} · sort={sort}"
        else:
            if sort not in {"", "new", "old"}:
                raise StoreError("sort must be new, old, views, comments, or hot", 400)
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
            note = info["description"]

        truncated = len(posts) > limit
        posts = posts[:limit]
        authentications = {post.id: self.board.store.post_authentication(post) for post in posts}
        engagement = self._engagement_map(posts)
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(posts, authentications, engagement),
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
                note=note,
                authentications=authentications,
                engagement=engagement,
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

        posts, capped = self.board.store.search_posts(spec, limit=limit)
        truncated = len(posts) > limit
        visible = posts[:limit]
        authentications = {post.id: self.board.store.post_authentication(post) for post in visible}
        engagement = self._engagement_map(visible)
        if (_param(params, "format") or "").lower() in {"json", "ndjson"}:
            self._send(
                200,
                posts_to_ndjson(visible, authentications, engagement),
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
                note=note,
                authentications=authentications,
                engagement=engagement,
            ),
        )

    def _publish(self, params: Params, uploads: Uploads, method: str) -> None:
        edit = _param(params, "edit")
        delete = _param(params, "delete")
        if edit is not None and delete is not None:
            raise StoreError("choose exactly one of edit or delete", 400)
        if edit is not None:
            self._edit(_post_id(edit), params, uploads, method)
            return
        if delete is not None:
            if uploads:
                raise StoreError("delete does not accept file uploads", 400)
            self._delete(_post_id(delete), params)
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
        body, title, name, _ = store.prepare_post(
            body=_required(params, "text"),
            title=_param(params, "title") or "",
            name=_param(params, "name") or "anonymous",
            max_body_bytes=_body_limit(self.board.cfg, method),
        )
        files = store.prepare_files(uploads)
        manifest = tuple(file.manifest() for file in files)
        key, sig = _auth_fields(params)
        auth = None
        if key is not None:
            canonical_key, signer_id = public_identity(key)
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
        store.delete_post(post)
        self.board.engagement.remove_post(post.id, post.board)
        self._sync_reply_count(parent_id)
        self._send(200, render_ok(ok=1, action="delete", id=post_id, actor_id=actor_id))


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
        board = board_raw.lower()
    elif parent is not None:
        board = parent.board
    else:
        raise StoreError("board is required", 400)

    if parent is not None and parent.board != board:
        raise StoreError("reply must stay in the parent topic", 400)
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
