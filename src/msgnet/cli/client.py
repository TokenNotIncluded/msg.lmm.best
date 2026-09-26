"""Client entry point. Private keys remain local; never print them or put them in URLs."""

import argparse
from pathlib import Path
lazy import base64
lazy import os
lazy import sys
lazy import urllib.parse
lazy import urllib.request

lazy from cryptography.hazmat.primitives import serialization
lazy from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msg", description="msgnet local identity tools")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create an Ed25519 identity without overwriting a key")
    init.add_argument("--key", type=Path, required=True)
    sign = commands.add_parser("sign", help="sign exact stdin bytes locally; prints only signature")
    sign.add_argument("--key", type=Path, required=True)
    get = commands.add_parser("get", help="read a same-server path with bounded response size")
    get.add_argument("path")
    get.add_argument("--server", required=True)
    args = parser.parse_args(argv)
    if args.command == "get":
        server = urllib.parse.urlsplit(args.server)
        if (
            server.scheme not in ("https", "http")
            or not server.netloc
            or server.username
            or server.password
        ):
            parser.error("server must be an HTTP(S) origin without credentials")
        if server.path not in ("", "/") or server.query or server.fragment:
            parser.error("server must be an origin, not a path")
        if not args.path.startswith("/") or args.path.startswith("//") or "\\" in args.path:
            parser.error("expected an absolute same-server path")
        with urllib.request.urlopen(args.server.rstrip("/") + args.path, timeout=10) as response:
            body = response.read(1_048_577)
        if len(body) > 1_048_576:
            parser.error("response exceeds limit")
        sys.stdout.buffer.write(body)
        return 0
    if args.command == "init":
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(args.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(pem)
            stream.flush()
            os.fsync(stream.fileno())
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        print(base64.b64encode(public).decode())
    else:
        raw = args.key.read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("expected Ed25519 private key")
        body = sys.stdin.buffer.read(1_048_577)
        if len(body) > 1_048_576:
            raise ValueError("payload too large")
        print(base64.b64encode(key.sign(body)).decode())
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
