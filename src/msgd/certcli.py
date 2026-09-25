"""CLI for Ed25519 keys and msgd authorization certificates."""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.crypto import (
    certificate_payload,
    make_certificate,
    public_identity,
    request_payload,
)

DEFAULT_PRIVATE = "/etc/msg-lmm-best/root-ca.key"
DEFAULT_PUBLIC = "/etc/msg-lmm-best/root-ca.pub"
DEFAULT_API = "http://127.0.0.1:3111"


def _load_private(path: str) -> Ed25519PrivateKey:
    value = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(value, Ed25519PrivateKey):
        raise SystemExit("private key is not Ed25519")
    return value


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _sign_b64(key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.b64encode(key.sign(payload)).decode("ascii")


def _post(url: str, fields: dict[str, str]) -> str:
    request = Request(
        url,
        data=urlencode(fields).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(request, timeout=15) as response:
        return response.read().decode("utf-8")


def _write_private(path: Path, key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _parse_grants(values: list[str]) -> dict[str, set[str]]:
    grants: dict[str, set[str]] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit("--grant must be TOPIC=action,action")
        topic, actions_raw = value.split("=", 1)
        actions = {action.strip() for action in actions_raw.split(",") if action.strip()}
        if not topic or not actions:
            raise SystemExit("--grant must include topic and actions")
        grants.setdefault(topic, set()).update(actions)
    return grants


def command_init(args: argparse.Namespace) -> int:
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)

    have_private = private_path.exists()
    have_public = public_path.exists()
    if have_public and not have_private:
        raise SystemExit("root CA private key is missing; refusing to rotate the trust anchor")

    if have_private:
        key = _load_private(str(private_path))
        os.chmod(private_path, 0o600)
        public = _public_b64(key)
        if have_public:
            stored = public_path.read_text(encoding="utf-8").strip()
            if stored != public:
                raise SystemExit("root CA public key does not match the private key")
        else:
            public_path.parent.mkdir(parents=True, exist_ok=True)
            public_path.write_text(public + "\n", encoding="utf-8")
    else:
        key = Ed25519PrivateKey.generate()
        _write_private(private_path, key)
        public = _public_b64(key)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.write_text(public + "\n", encoding="utf-8")

    os.chmod(public_path, 0o644)
    _, root_id = public_identity(public)
    print(f"root_id={root_id}")
    print(f"public_key={public}")
    return 0


def command_keygen(args: argparse.Namespace) -> int:
    path = Path(args.out)
    if path.exists():
        raise SystemExit(f"refusing to overwrite {path}")
    key = Ed25519PrivateKey.generate()
    _write_private(path, key)
    public = _public_b64(key)
    _, identity = public_identity(public)
    print(f"author_id={identity}")
    print(f"public_key={public}")
    return 0


def command_issue(args: argparse.Namespace) -> int:
    key = _load_private(args.key)
    issuer_key = _public_b64(key)
    _, issuer_id = public_identity(issuer_key)
    now = int(time.time())
    cert = make_certificate(
        serial=args.serial or secrets.token_hex(16),
        issuer_serial=args.issuer_serial,
        issuer_id=issuer_id,
        subject_key=args.subject_key,
        not_before=now - 60,
        not_after=now + args.days * 86400,
        delegate=args.delegate,
        grants=_parse_grants(args.grant),
    )
    signature = _sign_b64(key, certificate_payload(cert.body))
    if args.register:
        print(
            _post(
                args.api.rstrip("/") + "/_cert",
                {"cert": cert.body, "sig": signature},
            ).strip()
        )
    print(f"serial={cert.serial}")
    print(f"subject_id={cert.subject_id}")
    print(f"certificate={cert.body}")
    print(f"signature={signature}")
    return 0


def command_revoke(args: argparse.Namespace) -> int:
    key = _load_private(args.key)
    public = _public_b64(key)
    _, signer_id = public_identity(public)
    payload = request_payload(
        action="cert.revoke",
        signer_id=signer_id,
        version=1,
        serial=args.serial,
        reason=args.reason,
    )
    signature = _sign_b64(key, payload)
    print(
        _post(
            args.api.rstrip("/") + "/_revoke",
            {
                "serial": args.serial,
                "key": public,
                "sig": signature,
                "reason": args.reason,
            },
        ).strip()
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msgd-cert")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-root", help="create the server root CA if absent")
    init.add_argument("--private-key", default=DEFAULT_PRIVATE)
    init.add_argument("--public-key", default=DEFAULT_PUBLIC)
    init.set_defaults(func=command_init)

    keygen = sub.add_parser("keygen", help="create an Ed25519 identity key")
    keygen.add_argument("--out", required=True)
    keygen.set_defaults(func=command_keygen)

    issue = sub.add_parser("issue", help="issue and optionally register a certificate")
    issue.add_argument("--key", default=DEFAULT_PRIVATE)
    issue.add_argument("--issuer-serial", default="root")
    issue.add_argument("--subject-key", required=True)
    issue.add_argument("--grant", action="append", required=True)
    issue.add_argument("--delegate", action="store_true")
    issue.add_argument("--days", type=int, default=365)
    issue.add_argument("--serial", default=None)
    issue.add_argument("--api", default=DEFAULT_API)
    issue.add_argument("--register", action=argparse.BooleanOptionalAction, default=True)
    issue.set_defaults(func=command_issue)

    revoke = sub.add_parser("revoke", help="revoke a certificate with its issuer key")
    revoke.add_argument("serial")
    revoke.add_argument("--key", default=DEFAULT_PRIVATE)
    revoke.add_argument("--api", default=DEFAULT_API)
    revoke.add_argument("--reason", default="")
    revoke.set_defaults(func=command_revoke)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"msgd-cert: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
