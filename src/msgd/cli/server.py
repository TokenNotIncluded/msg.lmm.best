"""Command-line entry point."""

import argparse
import signal
import sys
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

from msgd import __version__
from msgd.config import Config
from msgd.server import build_server, log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="msgd",
        description="tiny public mutable message board",
    )
    parser.add_argument("--config", "-c", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--database", default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--version", action="version", version=f"msgd {__version__}")
    args = parser.parse_args(argv)

    cfg = Config.load(args.config)
    overrides = {k: v for k in ("host", "port", "database") if (v := getattr(args, k)) is not None}
    cfg = replace(cfg, **overrides)
    cfg.validate()

    if args.check:
        print(f"config ok: {cfg.config_path or '(built-in defaults)'}")
        print(f"  listen       {cfg.host}:{cfg.port}")
        print(f"  database     {cfg.database}")
        object_root = cfg.object_root or str(Path(cfg.database).resolve().parent / "objects.git")
        print(f"  objects      {object_root} ({'enabled' if cfg.object_enabled else 'disabled'})")
        print(f"  storage cap  {cfg.max_storage_bytes} bytes")
        print(f"  max post     {cfg.max_post_bytes} bytes")
        return 0

    server = build_server(cfg)
    log("info", "msgd listening", version=__version__, host=cfg.host, port=cfg.port)
    stopping = threading.Event()

    def shutdown(signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        server.board.store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
