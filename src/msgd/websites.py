"""Certificate-gated static web hosting for signed identities."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from msgd.crypto import SignedRequest
from msgd.store import StoreError, valid_author_id

if TYPE_CHECKING:
    from msgd.config import Config
    from msgd.store import Store

WEB_PATH_MAX_BYTES = 1024


@dataclass(frozen=True)
class WebFile:
    path: str
    data: bytes
    content_type: str
    sha256: str

    @property
    def nbytes(self) -> int:
        return len(self.data)


class WebSiteService:
    """Serve and mutate bounded per-identity static file trees."""

    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        if cfg.web_root:
            root = Path(cfg.web_root).expanduser()
        else:
            database = Path(cfg.database).expanduser()
            root = database.parent / "web"
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @staticmethod
    def normalize_path(value: str, *, allow_empty: bool = False) -> str:
        if "\x00" in value or "\\" in value:
            raise StoreError("web path contains an invalid character", 400)
        raw = value.strip("/")
        if not raw:
            if allow_empty:
                return ""
            raise StoreError("web path is required", 400)
        if len(raw.encode("utf-8")) > WEB_PATH_MAX_BYTES:
            raise StoreError(f"web path exceeds {WEB_PATH_MAX_BYTES} UTF-8 bytes", 413)
        parts = raw.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise StoreError("web path contains an invalid segment", 400)
        if any(len(part.encode("utf-8")) > 255 for part in parts):
            raise StoreError("web path segment exceeds 255 UTF-8 bytes", 413)
        return "/".join(parts)

    def _site_dir(self, author_id: str) -> Path:
        if not valid_author_id(author_id):
            raise StoreError("invalid web owner id", 400)
        return (self.root / author_id).resolve()

    def _path(self, author_id: str, path: str, *, allow_empty: bool = False) -> tuple[str, Path]:
        normalized = self.normalize_path(path, allow_empty=allow_empty)
        site = self._site_dir(author_id)
        candidate = (site / normalized).resolve()
        if not candidate.is_relative_to(site):
            raise StoreError("web path escapes site root", 400)
        return normalized, candidate

    def allowed(self, signer_id: str, action: str) -> bool:
        root = self.store.root_info()
        if root is not None and signer_id == root["root_id"]:
            return True
        return action in self.store.permissions_for(signer_id, "*")

    def usage(self, author_id: str) -> int:
        with self._lock:
            site = self._site_dir(author_id)
            if not site.exists():
                return 0
            total = 0
            for entry in site.rglob("*"):
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            return total

    def read(self, author_id: str, path: str) -> WebFile | None:
        normalized, candidate = self._path(author_id, path, allow_empty=True)
        site = self._site_dir(author_id)
        if not normalized:
            candidate = site / "index.html"
            normalized = "index.html"
        elif candidate.is_dir():
            candidate = candidate / "index.html"
            normalized = normalized.rstrip("/") + "/index.html"

        try:
            resolved = candidate.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(site):
            return None
        if not resolved.is_file() or resolved.is_symlink():
            return None
        try:
            data = resolved.read_bytes()
        except OSError:
            return None

        guessed, _encoding = mimetypes.guess_type(normalized)
        content_type = guessed or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {
            "application/javascript",
            "application/json",
            "application/xml",
            "image/svg+xml",
        }:
            content_type += "; charset=utf-8"
        return WebFile(
            path=normalized,
            data=data,
            content_type=content_type,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def write(
        self,
        *,
        auth: SignedRequest,
        path: str,
        data: bytes,
        content_type: str,
    ) -> dict[str, object]:
        if not self.allowed(auth.signer_id, "web.write"):
            raise StoreError("certificate does not grant web.write", 403)

        normalized, destination = self._path(auth.signer_id, path)
        # Burn the one-time nonce before state-dependent checks so a signed
        # mutation that fails today cannot be replayed after site state changes.
        self.store.consume_nonce(auth)
        if len(data) > self.cfg.web_max_site_bytes:
            raise StoreError(
                f"web file exceeds per-site quota={self.cfg.web_max_site_bytes}",
                413,
            )

        with self._lock:
            existing = 0
            if destination.exists():
                if destination.is_symlink() or not destination.is_file():
                    raise StoreError("web path conflicts with a non-file entry", 409)
                existing = destination.stat().st_size

            used_before = self.usage(auth.signer_id)
            used_after = used_before - existing + len(data)
            if used_after > self.cfg.web_max_site_bytes:
                raise StoreError(
                    f"web site exceeds quota={self.cfg.web_max_site_bytes} bytes",
                    413,
                )

            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(
                f".{destination.name}.{secrets.token_hex(8)}.tmp"
            )
            try:
                temporary.write_bytes(data)
                os.chmod(temporary, 0o644)
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    temporary.unlink(missing_ok=True)

            return {
                "ok": 1,
                "path": normalized,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "content_type": content_type,
                "used_bytes": used_after,
                "quota_bytes": self.cfg.web_max_site_bytes,
            }

    def delete(self, *, auth: SignedRequest, path: str) -> dict[str, object]:
        if not self.allowed(auth.signer_id, "web.delete"):
            raise StoreError("certificate does not grant web.delete", 403)

        normalized, target = self._path(auth.signer_id, path)
        # Consume first for the same replay reason as write().
        self.store.consume_nonce(auth)
        with self._lock:
            if not target.exists() or not target.is_file() or target.is_symlink():
                raise StoreError("web file not found", 404)

            target.unlink()

            site = self._site_dir(auth.signer_id)
            parent = target.parent
            while parent != site:
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent

            return {
                "ok": 1,
                "deleted": True,
                "path": normalized,
                "used_bytes": self.usage(auth.signer_id),
                "quota_bytes": self.cfg.web_max_site_bytes,
            }
