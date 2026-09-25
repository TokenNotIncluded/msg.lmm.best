"""Small Ed25519 primitives for identities, requests, and delegated certificates."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQUEST_MAGIC = b"msg.lmm.best/request/v1\n"
CERT_MAGIC = b"msg.lmm.best/cert/v1\n"

SERIAL_RE = re.compile(r"^[0-9a-f]{32}$")
IDENTITY_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")

ACTIONS = frozenset(
    {
        "post.create",
        "post.edit.self",
        "post.edit.any",
        "post.delete.self",
        "post.delete.any",
        "topic.policy",
        "cert.issue",
        "cert.revoke",
    }
)


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class SignedRequest:
    public_key: str
    signer_id: str
    signature: str
    version: int
    nonce: str | None = None
    issued: int | None = None


@dataclass(frozen=True)
class Certificate:
    serial: str
    issuer_serial: str
    issuer_id: str
    subject_key: str
    subject_id: str
    not_before: int
    not_after: int
    delegate: bool
    grants: dict[str, tuple[str, ...]]
    body: str


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def public_identity(value: str) -> tuple[str, str]:
    raw = _decode_b64(value, "key")
    if len(raw) != 32:
        raise SignatureError("ed25519 public key must be 32 raw bytes")
    canonical = base64.b64encode(raw).decode("ascii")
    return canonical, hashlib.sha256(raw).hexdigest()


def canonical_signature(value: str) -> str:
    raw = _decode_b64(value, "signature")
    if len(raw) != 64:
        raise SignatureError("ed25519 signature must be 64 bytes")
    return base64.b64encode(raw).decode("ascii")


def verify_detached(public_key: str, signature: str, payload: bytes) -> tuple[str, str, str]:
    canonical_key, signer_id = public_identity(public_key)
    canonical_sig = canonical_signature(signature)
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(canonical_key)).verify(
            base64.b64decode(canonical_sig),
            payload,
        )
    except InvalidSignature as exc:
        raise SignatureError("invalid ed25519 signature") from exc
    return canonical_key, signer_id, canonical_sig


def request_payload(
    *,
    action: str,
    signer_id: str,
    version: int,
    post_id: int | None = None,
    owner_id: str | None = None,
    nonce: str | None = None,
    issued: int | None = None,
    board: str = "",
    name: str = "",
    title: str = "",
    body: str = "",
    anonymous: tuple[str, ...] = (),
    serial: str = "",
    files: tuple[dict[str, object], ...] = (),
    reply_to: int | None = None,
    since: int | None = None,
    before: int | None = None,
    limit: int | None = None,
    csr_id: int | None = None,
    issuer_serial: str = "",
    subject_key: str = "",
    delegate: bool = False,
    grants: str = "",
    message: str = "",
    decision: str = "",
) -> bytes:
    if not IDENTITY_RE.fullmatch(signer_id):
        raise SignatureError("invalid signer id")

    fields: list[tuple[str, str]] = [
        ("action", action),
        ("signer_id", signer_id),
        ("version", str(version)),
    ]

    if action == "post.create":
        if nonce is None or issued is None:
            raise SignatureError("signed create requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("owner_id", signer_id),
            ("board", board),
            ("name", name),
            ("title", title),
            ("body", body),
            ("reply_to", "" if reply_to is None else str(reply_to)),
            ("files", canonical_json(list(files))),
        ]
    elif action == "post.edit":
        if post_id is None or owner_id is None:
            raise SignatureError("signed edit requires post_id and owner_id")
        fields += [
            ("post_id", str(post_id)),
            ("owner_id", owner_id),
            ("board", board),
            ("name", name),
            ("title", title),
            ("body", body),
            ("reply_to", "" if reply_to is None else str(reply_to)),
            ("files", canonical_json(list(files))),
        ]
    elif action == "post.delete":
        if post_id is None or owner_id is None:
            raise SignatureError("signed delete requires post_id and owner_id")
        fields += [
            ("post_id", str(post_id)),
            ("owner_id", owner_id),
            ("board", board),
        ]
    elif action == "topic.policy":
        fields += [
            ("board", board),
            ("anonymous", ",".join(sorted(anonymous))),
        ]
    elif action == "cert.revoke":
        if not SERIAL_RE.fullmatch(serial):
            raise SignatureError("invalid certificate serial")
        fields.append(("serial", serial))
    elif action == "inbox.read":
        if nonce is None or issued is None:
            raise SignatureError("inbox.read requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("since", "" if since is None else str(since)),
            ("before", "" if before is None else str(before)),
            ("limit", "" if limit is None else str(limit)),
        ]
    elif action == "cert.request":
        if nonce is None or issued is None:
            raise SignatureError("cert.request requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        canonical_subject, subject_id = public_identity(subject_key)
        if subject_id != signer_id:
            raise SignatureError("certificate request key must be the signing key")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("issuer_serial", issuer_serial),
            ("subject_key", canonical_subject),
            ("delegate", "1" if delegate else "0"),
            ("grants", grants),
            ("message", message),
        ]
    elif action == "cert.request.decision":
        if csr_id is None or csr_id < 1:
            raise SignatureError("cert.request.decision requires csr_id")
        if decision not in {"approve", "reject"}:
            raise SignatureError("decision must be approve or reject")
        fields += [
            ("csr_id", str(csr_id)),
            ("decision", decision),
        ]
    else:
        raise SignatureError(f"unsupported signed action: {action}")

    return REQUEST_MAGIC + b"".join(_field(key, value) for key, value in fields)


def signed_request(
    public_key: str,
    signature: str,
    payload: bytes,
    *,
    version: int,
    nonce: str | None = None,
    issued: int | None = None,
) -> SignedRequest:
    canonical_key, signer_id, canonical_sig = verify_detached(
        public_key,
        signature,
        payload,
    )
    return SignedRequest(
        public_key=canonical_key,
        signer_id=signer_id,
        signature=canonical_sig,
        version=version,
        nonce=nonce,
        issued=issued,
    )


def certificate_payload(body: str) -> bytes:
    cert = parse_certificate(body)
    return CERT_MAGIC + cert.body.encode("utf-8")


def parse_certificate(body: str) -> Certificate:
    try:
        raw = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SignatureError("certificate must be JSON") from exc
    if not isinstance(raw, dict) or raw.get("v") != 1:
        raise SignatureError("certificate v=1 required")

    serial = _string(raw, "serial")
    issuer_serial = _string(raw, "issuer_serial")
    issuer_id = _string(raw, "issuer_id")
    subject_key = _string(raw, "subject_key")
    subject_id = _string(raw, "subject_id")
    not_before = _integer(raw, "not_before")
    not_after = _integer(raw, "not_after")
    delegate = raw.get("delegate")
    grants_raw = raw.get("grants")

    if not SERIAL_RE.fullmatch(serial):
        raise SignatureError("invalid certificate serial")
    if issuer_serial != "root" and not SERIAL_RE.fullmatch(issuer_serial):
        raise SignatureError("invalid issuer_serial")
    if not IDENTITY_RE.fullmatch(issuer_id):
        raise SignatureError("invalid issuer_id")
    canonical_key, expected_id = public_identity(subject_key)
    if subject_id != expected_id:
        raise SignatureError("subject_id does not match subject_key")
    if not_before < 0 or not_after <= not_before:
        raise SignatureError("invalid certificate validity window")
    if not isinstance(delegate, bool):
        raise SignatureError("delegate must be boolean")
    if not isinstance(grants_raw, list) or not grants_raw:
        raise SignatureError("certificate grants are required")

    grants: dict[str, set[str]] = {}
    for grant in grants_raw:
        if not isinstance(grant, dict):
            raise SignatureError("grant must be an object")
        topic = _string(grant, "topic")
        actions = grant.get("actions")
        if topic != "*" and not _valid_topic(topic):
            raise SignatureError(f"invalid grant topic: {topic!r}")
        if not isinstance(actions, list) or not actions:
            raise SignatureError("grant actions are required")
        current = grants.setdefault(topic, set())
        for action in actions:
            if not isinstance(action, str) or action not in ACTIONS:
                raise SignatureError(f"invalid grant action: {action!r}")
            current.add(action)

    normalized_grants = [
        {"topic": topic, "actions": sorted(actions)}
        for topic, actions in sorted(grants.items())
    ]
    normalized = {
        "delegate": delegate,
        "grants": normalized_grants,
        "issuer_id": issuer_id,
        "issuer_serial": issuer_serial,
        "not_after": not_after,
        "not_before": not_before,
        "serial": serial,
        "subject_id": subject_id,
        "subject_key": canonical_key,
        "v": 1,
    }
    canonical = canonical_json(normalized)
    return Certificate(
        serial=serial,
        issuer_serial=issuer_serial,
        issuer_id=issuer_id,
        subject_key=canonical_key,
        subject_id=subject_id,
        not_before=not_before,
        not_after=not_after,
        delegate=delegate,
        grants={topic: tuple(sorted(actions)) for topic, actions in grants.items()},
        body=canonical,
    )


def make_certificate(
    *,
    serial: str,
    issuer_serial: str,
    issuer_id: str,
    subject_key: str,
    not_before: int,
    not_after: int,
    delegate: bool,
    grants: dict[str, set[str] | tuple[str, ...] | list[str]],
) -> Certificate:
    canonical_key, subject_id = public_identity(subject_key)
    value = {
        "v": 1,
        "serial": serial,
        "issuer_serial": issuer_serial,
        "issuer_id": issuer_id,
        "subject_key": canonical_key,
        "subject_id": subject_id,
        "not_before": int(not_before),
        "not_after": int(not_after),
        "delegate": bool(delegate),
        "grants": [
            {"topic": topic, "actions": sorted(set(actions))}
            for topic, actions in sorted(grants.items())
        ],
    }
    return parse_certificate(canonical_json(value))


def normalize_file_manifest(value: Any) -> tuple[dict[str, object], ...]:
    if value in (None, "", []):
        return ()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise SignatureError("files must be JSON") from exc
    if not isinstance(value, list):
        raise SignatureError("files must be a JSON array")

    result: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            raise SignatureError("file manifest item must be an object")
        name = item.get("name")
        content_type = item.get("type")
        nbytes = item.get("bytes")
        sha256 = item.get("sha256")
        if not isinstance(name, str) or not name:
            raise SignatureError("file name is required")
        if not isinstance(content_type, str) or not content_type:
            raise SignatureError("file type is required")
        if not isinstance(nbytes, int) or isinstance(nbytes, bool) or nbytes < 0:
            raise SignatureError("file bytes must be a non-negative integer")
        if (
            not isinstance(sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
        ):
            raise SignatureError("file sha256 must be 64 lowercase hex characters")
        result.append(
            {
                "name": name,
                "type": content_type,
                "bytes": nbytes,
                "sha256": sha256,
            }
        )
    return tuple(result)


def payload_info(payload: bytes) -> dict[str, str]:
    return {
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _decode_b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SignatureError(f"{label} must be base64") from exc


def _field(name: str, value: str) -> bytes:
    raw = value.encode("utf-8")
    return name.encode("ascii") + b":" + str(len(raw)).encode("ascii") + b":" + raw + b"\n"


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise SignatureError(f"{key} must be a string")
    return item


def _integer(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise SignatureError(f"{key} must be an integer")
    return item


def _valid_topic(topic: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", topic))
