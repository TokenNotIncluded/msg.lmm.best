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
from nacl.signing import VerifyKey

REQUEST_MAGIC = b"msg.lmm.best/request/v1\n"
CERT_MAGIC = b"msg.lmm.best/cert/v1\n"

SERIAL_RE = re.compile(r"^[0-9a-f]{32}$")
IDENTITY_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ACTIONS = frozenset(
    {
        "post.create",
        "post.edit.self",
        "post.edit.any",
        "post.delete.self",
        "post.delete.any",
        "topic.policy",
        "profile.update",
        "ssh.list",
        "ssh.manage",
        "webhook.list",
        "webhook.manage",
        "keystore.list",
        "keystore.read",
        "keystore.write",
        "keystore.delete",
        "state.read",
        "state.write",
        "state.delete",
        "watch.read",
        "watch.manage",
        "inbox.read",
        "outbox.read",
        "web.write",
        "web.delete",
        "file.list",
        "file.create",
        "file.write",
        "file.archive",
        "file.purge",
        "repo.create",
        "repo.write",
        "repo.manage",
        "cert.issue",
        "cert.revoke",
    }
)

RESOURCE_SCOPES = frozenset(
    {
        "topic",
        "account",
        "ssh",
        "webhook",
        "keystore",
        "state",
        "watch",
        "mailbox",
        "files",
        "web",
        "repos",
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


def curve25519_public_key(value: str) -> str:
    """Derive the Curve25519 encryption public key for an Ed25519 identity."""
    canonical, _ = public_identity(value)
    curve_key = VerifyKey(base64.b64decode(canonical)).to_curve25519_public_key()
    return base64.b64encode(bytes(curve_key)).decode("ascii")


def canonical_signature(value: str) -> str:
    raw = _decode_b64(value, "signature")
    if len(raw) != 64:
        raise SignatureError("ed25519 signature must be 64 bytes")
    return base64.b64encode(raw).decode("ascii")


def normalize_grant_scope(value: str, *, legacy_topic: bool = False) -> str:
    """Normalize legacy topic grants and resource scopes to one internal form."""
    if legacy_topic:
        if value == "*":
            return "topic:*"
        if not _valid_topic(value):
            raise SignatureError(f"invalid grant topic: {value!r}")
        return f"topic:{value}"

    if ":" not in value:
        raise SignatureError(f"invalid grant scope: {value!r}")
    resource, target = value.split(":", 1)
    if resource not in RESOURCE_SCOPES or not target:
        raise SignatureError(f"invalid grant scope: {value!r}")
    if resource == "topic":
        if target != "*" and not _valid_topic(target):
            raise SignatureError(f"invalid topic scope: {value!r}")
    elif target not in {"self", "*"} and not IDENTITY_RE.fullmatch(target):
        raise SignatureError(
            f"{resource} scope target must be self, *, or a 64-hex identity"
        )
    return f"{resource}:{target}"


def concrete_scope(scope: str, subject_id: str) -> str:
    """Resolve resource:self relative to the certificate subject."""
    normalized = normalize_grant_scope(scope)
    resource, target = normalized.split(":", 1)
    if target == "self":
        if not IDENTITY_RE.fullmatch(subject_id):
            raise SignatureError("invalid subject id for self scope")
        target = subject_id
    return f"{resource}:{target}"


def scope_covers(grant_scope: str, requested_scope: str, *, subject_id: str) -> bool:
    """Return whether one certificate scope covers a concrete requested scope."""
    grant = concrete_scope(grant_scope, subject_id)
    requested = normalize_grant_scope(requested_scope)
    requested_resource, requested_target = requested.split(":", 1)
    grant_resource, grant_target = grant.split(":", 1)
    return grant_resource == requested_resource and (
        grant_target == "*" or grant_target == requested_target
    )


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
    anonymous: tuple[str, ...] | None = None,
    signed: tuple[str, ...] | None = None,
    serial: str = "",
    files: tuple[dict[str, object], ...] = (),
    reply_to: int | None = None,
    since: int | None = None,
    before: int | None = None,
    limit: int | None = None,
    csr_id: int | None = None,
    requested_issuer: str = "",
    delegate: bool = False,
    csr_grants: tuple[dict[str, object], ...] = (),
    message: str = "",
    reason: str = "",
    webhook_id: str = "",
    webhook_url: str = "",
    webhook_events: tuple[str, ...] = (),
    webhook_enabled: bool = True,
    profile_name: str = "",
    profile_bio: str = "",
    profile_public_key: str = "",
    state_name: str = "",
    state_value: str = "",
    watch_id: str = "",
    watch_kind: str = "",
    watch_target: str = "",
    ack_status: str = "",
    task_scope: str = "",
    keystore_name: str = "",
    keystore_ciphertext: str = "",
    keystore_sha256: str = "",
    web_path: str = "",
    web_sha256: str = "",
    web_bytes: int | None = None,
    web_content_type: str = "",
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
    elif action in {"post.delete", "post.purge"}:
        if post_id is None or owner_id is None:
            raise SignatureError(
                f"signed {action.removeprefix('post.')} requires post_id and owner_id"
            )
        fields += [
            ("post_id", str(post_id)),
            ("owner_id", owner_id),
            ("board", board),
        ]
        if action == "post.purge":
            fields.append(("reason", reason))
    elif action == "topic.policy":
        fields.append(("board", board))
        if anonymous is not None:
            fields.append(("anonymous", ",".join(sorted(anonymous))))
        if signed is not None:
            fields.append(("signed", ",".join(sorted(signed))))
    elif action == "cert.revoke":
        if not SERIAL_RE.fullmatch(serial):
            raise SignatureError("invalid certificate serial")
        fields += [
            ("serial", serial),
            ("reason", reason),
        ]
    elif action == "cert.request":
        if nonce is None or issued is None:
            raise SignatureError("cert.request requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        if requested_issuer and not IDENTITY_RE.fullmatch(requested_issuer):
            raise SignatureError("requested_issuer must be an author id")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("requested_issuer", requested_issuer),
            ("delegate", "1" if delegate else "0"),
            ("grants", canonical_json(list(csr_grants))),
            ("message", message),
        ]
    elif action in {"cert.request.cancel", "cert.request.reject"}:
        if csr_id is None or csr_id < 1:
            raise SignatureError(f"{action} requires csr_id")
        fields += [
            ("csr_id", str(csr_id)),
            ("reason", reason),
        ]
    elif action in {"post.like", "post.unlike"}:
        if post_id is None or post_id < 1:
            raise SignatureError(f"{action} requires post_id")
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("post_id", str(post_id)),
        ]
    elif action in {"inbox.read", "outbox.read"}:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("since", "" if since is None else str(since)),
            ("before", "" if before is None else str(before)),
            ("limit", "" if limit is None else str(limit)),
        ]
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
    elif action in {"state.read", "state.write", "state.delete"}:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("state_name", state_name),
        ]
        if action == "state.write":
            fields.append(("state_value", state_value))
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
    elif action in {"watch.add", "watch.delete", "watch.list"}:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("watch_id", watch_id),
            ("watch_kind", watch_kind),
            ("watch_target", watch_target),
        ]
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
    elif action in {"inbox.ack", "post.ack"}:
        if post_id is None or post_id < 1:
            raise SignatureError(f"{action} requires post_id")
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("post_id", str(post_id)),
            ("ack_status", ack_status),
        ]
    elif action in {"task.open", "task.claim", "task.release", "task.complete", "task.list"}:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        if action != "task.list" and (post_id is None or post_id < 1):
            raise SignatureError(f"{action} requires post_id")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("post_id", "" if post_id is None else str(post_id)),
            ("task_scope", task_scope),
            ("limit", "" if limit is None else str(limit)),
        ]
    elif action in {"keystore.put", "keystore.delete"}:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("keystore_name", keystore_name),
        ]
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
        if action == "keystore.put":
            fields += [
                ("keystore_ciphertext", keystore_ciphertext),
                ("keystore_sha256", keystore_sha256),
            ]
    elif action in {
        "webhook.create",
        "webhook.update",
        "webhook.delete",
        "webhook.list",
        "webhook.test",
        "webhook.rotate",
    }:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("webhook_id", webhook_id),
            ("webhook_url", webhook_url),
            ("webhook_events", canonical_json(sorted(webhook_events))),
            ("webhook_enabled", "1" if webhook_enabled else "0"),
        ]
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
    elif action in {"web.write", "web.delete"}:
        if nonce is None or issued is None:
            raise SignatureError(f"{action} requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("web_path", web_path),
        ]
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
        if action == "web.write":
            if web_bytes is None or web_bytes < 0:
                raise SignatureError("web.write requires a non-negative byte count")
            if not SHA256_RE.fullmatch(web_sha256):
                raise SignatureError("web.write requires a lowercase sha256")
            fields += [
                ("web_sha256", web_sha256),
                ("web_bytes", str(web_bytes)),
                ("web_content_type", web_content_type),
            ]
    elif action == "profile.update":
        if nonce is None or issued is None:
            raise SignatureError("profile.update requires nonce and issued")
        if not NONCE_RE.fullmatch(nonce):
            raise SignatureError("nonce must be 32 lowercase hex characters")
        fields += [
            ("nonce", nonce),
            ("issued", str(issued)),
            ("profile_name", profile_name),
            ("profile_bio", profile_bio),
            ("profile_public_key", profile_public_key),
        ]
        if owner_id is not None:
            fields.append(("owner_id", owner_id))
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
    grant_wire: dict[str, tuple[str, str]] = {}
    for grant in grants_raw:
        if not isinstance(grant, dict):
            raise SignatureError("grant must be an object")
        has_topic = isinstance(grant.get("topic"), str)
        has_scope = isinstance(grant.get("scope"), str)
        if has_topic == has_scope:
            raise SignatureError("grant requires exactly one of topic or scope")
        if has_topic:
            raw_scope = _string(grant, "topic")
            scope = normalize_grant_scope(raw_scope, legacy_topic=True)
            wire = ("topic", raw_scope)
        else:
            raw_scope = _string(grant, "scope")
            scope = normalize_grant_scope(raw_scope)
            wire = ("scope", scope)
        actions = grant.get("actions")
        if not isinstance(actions, list) or not actions:
            raise SignatureError("grant actions are required")
        current = grants.setdefault(scope, set())
        grant_wire.setdefault(scope, wire)
        for action in actions:
            if not isinstance(action, str) or action not in ACTIONS:
                raise SignatureError(f"invalid grant action: {action!r}")
            current.add(action)

    normalized_grants = []
    for scope, actions in sorted(grants.items()):
        field, value = grant_wire[scope]
        normalized_grants.append({field: value, "actions": sorted(actions)})
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
            (
                {"topic": scope, "actions": sorted(set(actions))}
                if scope == "*" or _valid_topic(scope)
                else {
                    "scope": normalize_grant_scope(scope),
                    "actions": sorted(set(actions)),
                }
            )
            for scope, actions in sorted(grants.items())
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
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
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
    return bool(re.fullmatch(r"[a-z][a-z0-9]{1,23}", topic))
