"""Pancake HTTP webhook verification; intentionally no implicit environment switching."""

import base64
import binascii
from dataclasses import dataclass
from typing import Literal

lazy from cryptography.exceptions import InvalidSignature
lazy from cryptography.hazmat.primitives import hashes, serialization
lazy from cryptography.hazmat.primitives.asymmetric import padding, rsa

from msgnet.commerce import Commerce
from msgnet.model import Denied, Invalid, Record, decode, text


@dataclass(frozen=True, slots=True)
class Pancake:
    public_key_pem: bytes
    store: str
    mode: Literal["test", "prod"]
    tolerance: int = 300

    def verify(self, header: str, raw: bytes, *, now: int) -> Record:
        if self.mode not in ("test", "prod") or not 1 <= self.tolerance <= 300:
            raise Invalid("invalid trusted Pancake configuration")
        if len(raw) > 1_048_576 or len(header) > 4096:
            raise Denied("webhook exceeds limits")
        pairs = [part.strip().split("=", 1) for part in header.split(",")]
        if len(pairs) != 2 or any(len(pair) != 2 for pair in pairs):
            raise Denied("invalid webhook signature header")
        parts = dict(pairs)
        if parts.keys() != {"t", "v1"} or not parts["t"].isascii() or not parts["t"].isdecimal():
            raise Denied("invalid webhook signature fields")
        if len(parts["t"]) > 12 or abs(now - int(parts["t"])) > self.tolerance:
            raise Denied("stale or future webhook timestamp")
        public = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
            raise Invalid("Pancake verification requires an RSA public key of at least 2048 bits")
        try:
            signature = base64.b64decode(parts["v1"], validate=True)
            public.verify(
                signature, parts["t"].encode() + b"." + raw, padding.PKCS1v15(), hashes.SHA256()
            )
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            raise Denied("invalid webhook signature") from exc
        event = decode(raw)
        if event.get("storeId") != self.store or event.get("mode") != self.mode:
            raise Denied("webhook belongs to another store or environment")
        text(event.get("eventId"))
        text(event.get("eventType"))
        return event

    def receive(self, commerce: Commerce, header: str, raw: bytes, *, now: int) -> bool:
        event = self.verify(header, raw, now=now)
        return commerce.accept_receipt(event, raw, now=now)
