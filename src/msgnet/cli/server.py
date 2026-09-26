"""Operator entry point. Help and parsing do not import storage/crypto/network modules."""

import argparse
from pathlib import Path
lazy import sys

lazy import uvicorn

lazy from msgnet.adapters.http import create_app
lazy from msgnet.config import Config
lazy from msgnet.content import Content
lazy from msgnet.database import Database
lazy from msgnet.ledger import Ledger
lazy from msgnet.objects import Objects


def _run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msgd", description="msgnet server/operator tools")
    parser.add_argument("--config", type=Path, default=Path("/etc/msg.lmm.best/config.toml"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="initialize NEW storage; never migrate a legacy database")
    commands.add_parser("check", help="verify committed content is readable")
    serve = commands.add_parser("serve", help="run the read-only development HTTP server")
    serve.add_argument("--development", action="store_true", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    commands.add_parser("gc", help="exclusively locked object reconciliation and normal Git GC")
    balance = commands.add_parser("balance", help="read a local account's USD cents")
    balance.add_argument("account")
    args = parser.parse_args(argv)
    config = Config.load(args.config)
    database = Database(config.data)
    content = Content(database, Objects(config.data / "objects.git", config.max_object_bytes))
    match args.command:
        case "serve":
            uvicorn.run(
                create_app(content),
                host=args.host,
                port=args.port,
                workers=1,
                proxy_headers=False,
                server_header=False,
            )
        case "init":
            content.initialize()
            print("storage initialized; rewrite is not yet a production replacement")
        case "gc":
            print(f"orphan pins removed: {content.collect()}")
        case "balance":
            print(Ledger(database).balance(args.account))
        case "check":
            with database.transaction(write=False) as tx:
                rows = tx.all("SELECT DISTINCT oid FROM revisions")
                for row in rows:
                    if not isinstance(row[0], str):
                        raise ValueError("invalid object ID in metadata")
                    content.objects.get(row[0])
            print(f"verified {len(rows)} referenced objects")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
