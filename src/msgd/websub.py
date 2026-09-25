"""WebSub hub for public RSS feeds."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import secrets
import socket
import ssl
import threading
import time
from contextlib import suppress
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from msgd.config import Config
from msgd.render import render_rss
from msgd.store import Store, StoreError, valid_board_name
from msgd.webhooks import RETRY_DELAYS, SecretBox, _public_addresses, validate_webhook_url

CONTENT_TYPE = "application/rss+xml; charset=utf-8"
VERIFY_RETRY_DELAYS = (5.0, 30.0, 300.0)
MAX_VERIFICATION_RESPONSE_BYTES = 8192


def _subscription_id(topic: str, callback: str) -> str:
    return hashlib.sha256(f"{topic}\n{callback}".encode()).hexdigest()


def normalize_topic(cfg: Config, store: Store, value: str) -> str:
    raw = value.strip()
    try:
        parsed = urlsplit(raw)
        expected = urlsplit(f"https://{cfg.site_name}")
    except ValueError as exc:
        raise StoreError("invalid WebSub topic URL", 400) from exc

    if parsed.scheme.lower() != "https" or parsed.netloc.lower() != expected.netloc.lower():
        raise StoreError("WebSub topic must be a feed on this site", 400)
    if parsed.username is not None or parsed.password is not None:
        raise StoreError("WebSub topic must not contain userinfo", 400)
    if parsed.query or parsed.fragment:
        raise StoreError("WebSub topic must be the advertised canonical feed URL", 400)

    path = parsed.path or "/"
    if path in {"/rss.xml", "/feed.xml"}:
        return f"https://{cfg.site_name}{path}"

    segments = [segment for segment in path.split("/") if segment]
    if (
        len(segments) == 2
        and segments[1] in {"rss.xml", "feed.xml"}
        and valid_board_name(segments[0])
        and store.board_info(segments[0]) is not None
    ):
        return f"https://{cfg.site_name}/{segments[0]}/{segments[1]}"

    raise StoreError("WebSub topic is not an advertised RSS feed", 400)


def _request_https(
    method: str,
    url: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    max_response_bytes: int = 4096,
) -> tuple[int, bytes]:
    parsed = urlsplit(validate_webhook_url(url))
    host = parsed.hostname or ""
    addresses = _public_addresses(host)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    last_error: OSError | None = None
    for address in addresses:
        sock: socket.socket | None = None
        tls = None
        try:
            sock = socket.create_connection((address, 443), timeout=timeout)
            context = ssl.create_default_context()
            tls = context.wrap_socket(sock, server_hostname=host)
            request_headers = {
                "Host": host,
                "Connection": "close",
                "User-Agent": "msgd-websub/1",
                **(headers or {}),
            }
            if body or method == "POST":
                request_headers["Content-Length"] = str(len(body))
            request = [f"{method} {path} HTTP/1.1"]
            request.extend(f"{key}: {value}" for key, value in request_headers.items())
            tls.sendall(("\r\n".join(request) + "\r\n\r\n").encode("ascii") + body)
            response = http.client.HTTPResponse(tls)
            response.begin()
            status = response.status
            payload = response.read(max_response_bytes + 1)
            response.close()
            if len(payload) > max_response_bytes:
                raise OSError("WebSub callback response is too large")
            return status, payload
        except OSError as exc:
            last_error = exc
        finally:
            if tls is not None:
                with suppress(OSError):
                    tls.close()
            elif sock is not None:
                with suppress(OSError):
                    sock.close()
    raise OSError(str(last_error or "WebSub callback request failed"))


def _verification_url(
    callback: str,
    *,
    mode: str,
    topic: str,
    challenge: str,
    lease_seconds: int,
) -> str:
    parsed = urlsplit(callback)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(
        [
            ("hub.mode", mode),
            ("hub.topic", topic),
            ("hub.challenge", challenge),
        ]
    )
    if mode == "subscribe":
        query.append(("hub.lease_seconds", str(lease_seconds)))
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            parsed.fragment,
        )
    )


def _verify_callback(
    callback: str,
    *,
    mode: str,
    topic: str,
    challenge: str,
    lease_seconds: int,
) -> bool:
    status, body = _request_https(
        "GET",
        _verification_url(
            callback,
            mode=mode,
            topic=topic,
            challenge=challenge,
            lease_seconds=lease_seconds,
        ),
        max_response_bytes=MAX_VERIFICATION_RESPONSE_BYTES,
    )
    return 200 <= status < 300 and body == challenge.encode("utf-8")


def _post_feed(callback: str, body: bytes, headers: dict[str, str]) -> int:
    status, _ = _request_https(
        "POST",
        callback,
        body=body,
        headers={"Content-Type": CONTENT_TYPE, **headers},
    )
    return status


class WebSubService:
    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self.secrets = SecretBox(cfg.webhook_secret_key)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        if cfg.websub_delivery_enabled:
            self._thread = threading.Thread(
                target=self._worker,
                name="msgd-websub",
                daemon=True,
            )
            self._thread.start()

    @property
    def hub_url(self) -> str:
        return f"https://{self.cfg.site_name}/hub"

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def request(
        self,
        *,
        mode: str,
        topic: str,
        callback: str,
        lease_seconds: str | None = None,
        secret: str = "",
    ) -> None:
        if mode not in {"subscribe", "unsubscribe"}:
            raise StoreError("hub.mode must be subscribe or unsubscribe", 400)

        topic = normalize_topic(self.cfg, self.store, topic)
        callback = validate_webhook_url(callback)

        if len(secret.encode("utf-8")) >= 200:
            raise StoreError("hub.secret must be less than 200 bytes", 400)

        if mode == "subscribe":
            if lease_seconds in {None, ""}:
                lease = self.cfg.websub_default_lease_seconds
            else:
                try:
                    requested_lease = int(lease_seconds)
                except ValueError as exc:
                    raise StoreError("hub.lease_seconds must be a positive integer", 400) from exc
                if requested_lease < 1:
                    raise StoreError("hub.lease_seconds must be a positive integer", 400)
                lease = min(requested_lease, self.cfg.websub_max_lease_seconds)
        else:
            lease = 0

        subscription_id = _subscription_id(topic, callback)
        if mode == "subscribe" and secret:
            secret_nonce, secret_ciphertext = self.secrets.encrypt(subscription_id, secret)
        else:
            secret_nonce, secret_ciphertext = b"", b""

        self.store.upsert_websub_verification(
            verification_id=subscription_id,
            mode=mode,
            topic=topic,
            callback=callback,
            lease_seconds=lease,
            challenge=secrets.token_urlsafe(32),
            secret_nonce=secret_nonce,
            secret_ciphertext=secret_ciphertext,
        )
        self._wake.set()

    def publish(self, board: str) -> list[str]:
        topics: list[str] = []
        if board != "index":
            topics.extend(
                [
                    f"https://{self.cfg.site_name}/rss.xml",
                    f"https://{self.cfg.site_name}/feed.xml",
                ]
            )
        if valid_board_name(board) and self.store.board_info(board) is not None:
            topics.extend(
                [
                    f"https://{self.cfg.site_name}/{board}/rss.xml",
                    f"https://{self.cfg.site_name}/{board}/feed.xml",
                ]
            )

        queued: list[str] = []
        for topic in topics:
            queued.extend(self.store.queue_websub_topic(topic))
        if queued:
            self._wake.set()
        return queued

    def _feed_body(self, topic: str) -> bytes:
        parsed = urlsplit(topic)
        path = parsed.path
        if path in {"/rss.xml", "/feed.xml"}:
            limit = min(50, self.cfg.max_limit)
            posts = [
                post for post in self.store.list_posts(limit=limit + 10) if post.board != "index"
            ][:limit]
            return render_rss(self.cfg, posts, feed_path=path).encode("utf-8")

        segments = [segment for segment in path.split("/") if segment]
        if len(segments) != 2 or segments[1] not in {"rss.xml", "feed.xml"}:
            raise StoreError("invalid WebSub topic", 400)
        board = segments[0]
        info = self.store.board_info(board)
        if info is None:
            raise StoreError("WebSub topic board no longer exists", 404)
        posts = self.store.list_posts(
            board=board,
            limit=min(50, self.cfg.max_limit),
            order="desc",
        )
        return render_rss(
            self.cfg,
            posts,
            board=board,
            description=str(info["description"]),
            feed_path=path,
        ).encode("utf-8")

    def _verify(self, row: dict[str, object]) -> None:
        verification_id = str(row["id"])
        mode = str(row["mode"])
        topic = str(row["topic"])
        callback = str(row["callback"])
        lease_seconds = int(row["lease_seconds"])
        challenge = str(row["challenge"])

        if not _verify_callback(
            callback,
            mode=mode,
            topic=topic,
            challenge=challenge,
            lease_seconds=lease_seconds,
        ):
            raise OSError("WebSub callback did not echo the verification challenge")

        if mode == "subscribe":
            self.store.activate_websub_subscription(
                subscription_id=verification_id,
                topic=topic,
                callback=callback,
                lease_seconds=lease_seconds,
                secret_nonce=bytes(row["secret_nonce"]),
                secret_ciphertext=bytes(row["secret_ciphertext"]),
            )
        else:
            self.store.delete_websub_subscription(topic, callback)
        self.store.delete_websub_verification(verification_id)

    def _deliver(self, row: dict[str, object]) -> None:
        subscription_id = str(row["subscription_id"])
        body = self._feed_body(str(row["topic"]))
        headers: dict[str, str] = {}
        ciphertext = bytes(row["secret_ciphertext"])
        if ciphertext:
            secret = self.secrets.decrypt(
                subscription_id,
                bytes(row["secret_nonce"]),
                ciphertext,
            )
            digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Hub-Signature"] = f"sha256={digest}"

        status = _post_feed(str(row["callback"]), body, headers)
        if not 200 <= status < 300:
            raise OSError(f"WebSub subscriber returned HTTP {status}")

    def _run_once(self) -> int:
        processed = 0
        for row in self.store.due_websub_verifications(20):
            processed += 1
            try:
                self._verify(row)
            except Exception as exc:
                attempts = int(row["attempts"])
                retry_after = VERIFY_RETRY_DELAYS[min(attempts, len(VERIFY_RETRY_DELAYS) - 1)]
                self.store.finish_websub_verification(
                    str(row["id"]),
                    success=False,
                    error=str(exc),
                    retry_after=retry_after,
                )

        for row in self.store.due_websub_deliveries(20):
            processed += 1
            try:
                self._deliver(row)
            except Exception as exc:
                attempts = int(row["attempts"])
                retry_after = RETRY_DELAYS[min(attempts, len(RETRY_DELAYS) - 1)]
                self.store.finish_websub_delivery(
                    str(row["id"]),
                    success=False,
                    error=str(exc),
                    retry_after=retry_after,
                )
            else:
                self.store.finish_websub_delivery(str(row["id"]), success=True)
        return processed

    def _worker(self) -> None:
        last_prune = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_prune >= 3600:
                self.store.prune_websub()
                last_prune = now
            processed = self._run_once()
            if processed:
                continue
            self._wake.wait(timeout=1.0)
            self._wake.clear()
