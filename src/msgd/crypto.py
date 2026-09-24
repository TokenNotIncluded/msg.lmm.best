"""Ed25519 identity and signed-post helpers."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAGIC = b"msg.lmm.best/sign/v1\n"
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class SignedState:
    public_key: str
    author_id: str
    signature: str
    version: int
    nonce: str | None = None
    issued: int | None = None


def public_identity(value: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SignatureError("key must be base64") from exc
    if len(raw) != 32:
        raise SignatureError("ed25519 public key must be 32 raw bytes")
    canonical = base64.b64encode(raw).decode("ascii")
    return canonical, hashlib.sha256(raw).hexdigest()


def canonical_signature(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SignatureError("signature must be base64") from exc
    if len(raw) != 64:
        raise SignatureError("ed25519 signature must be 64 bytes")
    return base64.b64encode(raw).decode("ascii")


def _field(name: str, value: str) -> bytes:
    raw = value.encode("utf-8")
    return name.encode("ascii") + b":" + str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def signing_payload(
    *,
    action: str,
    author_id: str,
    version: int,
    post_id: int | None = None,
    nonce: str | None = None,
    issued: int | None = None,
    board: str = "",
    name: str = "",
    title: str = "",
    body: str = "",
) -> bytes:
    parts = [
        ("action", action),
        ("author_id", author_id),
        ("version", str(version)),
    ]
    if action == "create":
        if nonce is None or issued is None:
            raise SignatureError("create signing requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        parts += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("board", board),
            ("name", name),
            ("title", title),
            ("body", body),
        ]
    elif action == "edit":
        if post_id is None:
            raise SignatureError("edit signing requires post_id")
        parts += [
            ("post_id", str(post_id)),
            ("board", board),
            ("name", name),
            ("title", title),
            ("body", body),
        ]
    elif action == "delete":
        if post_id is None:
            raise SignatureError("delete signing requires post_id")
        parts.append(("post_id", str(post_id)))
    else:
        raise SignatureError(f"unsupported signed action: {action}")

    return MAGIC + b"".join(_field(key, value) for key, value in parts)


def verify_signature(public_key: str, signature: str, payload: bytes) -> SignedState:
    canonical_key, author_id = public_identity(public_key)
    canonical_sig = canonical_signature(signature)
    raw_key = base64.b64decode(canonical_key)
    raw_sig = base64.b64decode(canonical_sig)
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_sig, payload)
    except InvalidSignature as exc:
        raise SignatureError("invalid ed25519 signature") from exc
    return SignedState(
        public_key=canonical_key,
        author_id=author_id,
        signature=canonical_sig,
        version=0,
    )


def payload_info(payload: bytes) -> dict[str, str]:
    return {
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
