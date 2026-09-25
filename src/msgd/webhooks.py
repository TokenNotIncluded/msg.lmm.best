"""Signed-user webhooks with persistent retries and SSRF-safe HTTPS delivery."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from msgd.config import Config
from msgd.store import Store, StoreError

WEBHOOK_EVENTS = frozenset(
    {
        "post.created",
        "post.updated",
        "post.deleted",
        "reply.created",
        "mention.created",
        "certificate.issued",
        "certificate.revoked",
    }
)
WEBHOOK_TEST_EVENT = "webhook.test"
RETRY_DELAYS = (30.0, 300.0, 1800.0, 7200.0, 43200.0)


def normalize_events(values: list[str] | tuple[str, ...] | set[str]) -> tuple[str, ...]:
    events = tuple(sorted({str(value).strip() for value in values if str(value).strip()}))
    if not events:
        raise StoreError("at least one webhook event is required", 400)
    invalid = set(events) - WEBHOOK_EVENTS
    if invalid:
        raise StoreError(f"unsupported webhook events: {sorted(invalid)}", 400)
    return events


def validate_webhook_url(value: str) -> str:
    raw = value.strip()
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise StoreError("webhook URL must not contain whitespace or control characters", 400)
    if len(raw.encode("utf-8")) > 2048:
        raise StoreError("webhook URL is too long", 400)
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "https":
        raise StoreError("webhook URL must use https", 400)
    if not parsed.hostname:
        raise StoreError("webhook URL requires a hostname", 400)
    if parsed.username is not None or parsed.password is not None:
        raise StoreError("webhook URL must not contain userinfo", 400)
    if parsed.fragment:
        raise StoreError("webhook URL must not contain a fragment", 400)
    try:
        port = parsed.port
    except ValueError as exc:
        raise StoreError("invalid webhook port", 400) from exc
    if port not in {None, 443}:
        raise StoreError("webhook URL must use HTTPS port 443", 400)

    host = parsed.hostname.rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise StoreError("webhook hostname must be ASCII DNS/punycode", 400)
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise StoreError("local webhook hostnames are not allowed", 400)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise StoreError("webhook URL must use a public DNS hostname, not an IP literal", 400)

    return raw


def _public_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError(f"webhook DNS lookup failed: {exc}") from exc

    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise OSError("webhook DNS returned an invalid address") from exc
        if not ip.is_global:
            raise OSError("webhook DNS resolved to a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError("webhook DNS returned no addresses")
    return addresses


class SecretBox:
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def _key(self) -> bytes:
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw = os.urandom(32)
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                data = self.path.read_bytes()
            else:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                data = raw
        if len(data) != 32:
            raise OSError(f"invalid webhook secret key file: {self.path}")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return data

    def encrypt(self, webhook_id: str, secret: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key()).encrypt(
            nonce,
            secret.encode("utf-8"),
            webhook_id.encode("ascii"),
        )
        return nonce, ciphertext

    def decrypt(self, webhook_id: str, nonce: bytes, ciphertext: bytes) -> str:
        value = AESGCM(self._key()).decrypt(
            nonce,
            ciphertext,
            webhook_id.encode("ascii"),
        )
        return value.decode("utf-8")


def delivery_signature(secret: str, timestamp: int, body: bytes) -> str:
    signed = str(timestamp).encode("ascii") + b"." + body
    return "sha256=" + hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def _post_https(url: str, body: bytes, headers: dict[str, str], *, timeout: float = 5.0) -> int:
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
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Connection": "close",
                "User-Agent": "msgd-webhook/1",
                **headers,
            }
            request = [f"POST {path} HTTP/1.1"]
            request.extend(f"{key}: {value}" for key, value in request_headers.items())
            tls.sendall(("\r\n".join(request) + "\r\n\r\n").encode("ascii") + body)
            response = http.client.HTTPResponse(tls)
            response.begin()
            status = response.status
            response.read(4096)
            response.close()
            return status
        except OSError as exc:
            last_error = exc
        finally:
            if tls is not None:
                try:
                    tls.close()
                except OSError:
                    pass
            elif sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise OSError(str(last_error or "webhook delivery failed"))


class WebhookService:
    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self.secrets = SecretBox(cfg.webhook_secret_key)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        if cfg.webhook_delivery_enabled:
            self._thread = threading.Thread(
                target=self._worker,
                name="msgd-webhooks",
                daemon=True,
            )
            self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @staticmethod
    def public_view(row: dict[str, object]) -> dict[str, object]:
        return {
            "id": row["id"],
            "url": row["url"],
            "events": list(row["events"]),
            "enabled": bool(row["enabled"]),
            "created": round(float(row["created"]), 3),
            "updated": round(float(row["updated"]), 3),
            "pending": int(row.get("pending", 0) or 0),
            "failed": int(row.get("failed", 0) or 0),
            "last_error": str(row.get("last_error", "")),
        }

    def create(self, owner_id: str, url: str, events: tuple[str, ...]) -> dict[str, object]:
        if self.store.webhook_count(owner_id) >= self.cfg.webhook_max_per_identity:
            raise StoreError(
                f"webhook limit reached; max={self.cfg.webhook_max_per_identity}",
                409,
            )
        url = validate_webhook_url(url)
        events = normalize_events(events)
        webhook_id = secrets.token_hex(16)
        secret = secrets.token_urlsafe(32)
        nonce, ciphertext = self.secrets.encrypt(webhook_id, secret)
        row = self.store.create_webhook(
            webhook_id=webhook_id,
            owner_id=owner_id,
            url=url,
            events=events,
            secret_nonce=nonce,
            secret_ciphertext=ciphertext,
        )
        result = self.public_view(row)
        result["secret"] = secret
        result["warning"] = "webhook secret is shown once; save it as a credential"
        return result

    def update(
        self,
        owner_id: str,
        webhook_id: str,
        *,
        url: str,
        events: tuple[str, ...],
        enabled: bool,
    ) -> dict[str, object]:
        row = self.store.update_webhook(
            webhook_id,
            owner_id,
            url=validate_webhook_url(url),
            events=normalize_events(events),
            enabled=enabled,
        )
        return self.public_view(row)

    def rotate(self, owner_id: str, webhook_id: str) -> dict[str, object]:
        row = self.store.webhook(webhook_id)
        if row is None or row["owner_id"] != owner_id:
            raise StoreError("webhook not found", 404)
        secret = secrets.token_urlsafe(32)
        nonce, ciphertext = self.secrets.encrypt(webhook_id, secret)
        self.store.rotate_webhook_secret(
            webhook_id,
            owner_id,
            secret_nonce=nonce,
            secret_ciphertext=ciphertext,
        )
        return {
            "id": webhook_id,
            "secret": secret,
            "warning": "old webhook secret is invalid now; save this new credential",
        }

    def list(self, owner_id: str) -> list[dict[str, object]]:
        return [self.public_view(row) for row in self.store.list_webhooks(owner_id)]

    def delete(self, owner_id: str, webhook_id: str) -> None:
        self.store.delete_webhook(webhook_id, owner_id)

    def emit(self, subject_id: str | None, event: str, data: dict[str, object]) -> list[str]:
        if not subject_id:
            return []
        if event not in WEBHOOK_EVENTS:
            raise ValueError(f"unknown webhook event: {event}")
        queued = self.store.queue_webhook_event(subject_id, event, data)
        if queued:
            self._wake.set()
        return queued

    def test(self, owner_id: str, webhook_id: str) -> str:
        queued = self.store.queue_webhook_event(
            owner_id,
            WEBHOOK_TEST_EVENT,
            {
                "message": "msg.lmm.best webhook test",
                "webhook_id": webhook_id,
            },
            only_webhook_id=webhook_id,
        )
        if not queued:
            row = self.store.webhook(webhook_id)
            if row is None or row["owner_id"] != owner_id:
                raise StoreError("webhook not found", 404)
            if not row["enabled"]:
                raise StoreError("webhook is disabled", 409)
            raise StoreError("webhook test could not be queued", 409)
        self._wake.set()
        return queued[0]

    def _delivery_body(self, row: dict[str, object]) -> bytes:
        payload = {
            "v": 1,
            "delivery_id": str(row["id"]),
            "event": str(row["event"]),
            "created": round(float(row["created"]), 3),
            "subject_id": str(row["subject_id"]),
            "data": json.loads(str(row["data"])),
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _deliver(self, row: dict[str, object]) -> None:
        webhook_id = str(row["webhook_id"])
        secret = self.secrets.decrypt(
            webhook_id,
            bytes(row["secret_nonce"]),
            bytes(row["secret_ciphertext"]),
        )
        body = self._delivery_body(row)
        timestamp = int(time.time())
        signature = delivery_signature(secret, timestamp, body)
        status = _post_https(
            str(row["url"]),
            body,
            {
                "X-Msg-Event": str(row["event"]),
                "X-Msg-Delivery": str(row["id"]),
                "X-Msg-Webhook": webhook_id,
                "X-Msg-Timestamp": str(timestamp),
                "X-Msg-Signature": signature,
            },
        )
        if not 200 <= status < 300:
            raise OSError(f"webhook returned HTTP {status}")

    def _run_once(self) -> int:
        rows = self.store.due_webhook_deliveries(20)
        for row in rows:
            try:
                self._deliver(row)
            except Exception as exc:
                attempts = int(row["attempts"])
                retry_after = RETRY_DELAYS[min(attempts, len(RETRY_DELAYS) - 1)]
                self.store.finish_webhook_delivery(
                    str(row["id"]),
                    success=False,
                    error=str(exc),
                    retry_after=retry_after,
                )
            else:
                self.store.finish_webhook_delivery(str(row["id"]), success=True)
        return len(rows)

    def _worker(self) -> None:
        while not self._stop.is_set():
            processed = self._run_once()
            if processed:
                continue
            self._wake.wait(timeout=1.0)
            self._wake.clear()
