"""Command line entry point: `msgd --config /etc/msg-lmm-best/msg.conf`."""

import argparse
import signal
import sys
import threading
from dataclasses import replace
from typing import Any

from msgd import __version__
from msgd.config import Config
from msgd.server import build_server, log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="msgd", description="GET-first message board")
    parser.add_argument(
        "--config",
        "-c",
        default=None,
        help="path to msg.conf (default: /etc/msg-lmm-best/msg.conf)",
    )
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--database", default=None)
    parser.add_argument("--check", action="store_true", help="validate the config and exit")
    parser.add_argument("--version", action="version", version=f"msgd {__version__}")
    args = parser.parse_args(argv)

    cfg = Config.load(args.config)
    overrides = {k: v for k in ("host", "port", "database") if (v := getattr(args, k))}
    cfg = replace(cfg, **overrides)
    cfg.validate()

    if args.check:
        print(f"config ok: {cfg.config_path or '(built-in defaults)'}")
        print(f"  version     {__version__}")
        print(f"  listen      {cfg.host}:{cfg.port}")
        print(f"  database    {cfg.database}")
        print(f"  max post    {cfg.max_post_bytes} bytes")
        print(f"  board cap   {cfg.max_posts_per_board} entries")
        print(f"  creates     {cfg.create_per_hour}/hour per client")
        print(f"  dedup       {cfg.dedup_hours or 'forever'} hours")
        print(f"  hide at     {cfg.hide_threshold} flags")
        print(f"  files       {'enabled' if cfg.files_enabled else 'disabled'}")
        print(f"  gated       {'yes' if cfg.write_token else 'no'}")
        print(f"  operator    {'token loaded' if cfg.admin_token else 'none'}")
        return 0

    server = build_server(cfg)
    log(
        "info",
        "msgd listening",
        version=__version__,
        host=cfg.host,
        port=cfg.port,
        db=cfg.database,
        config=cfg.config_path or "defaults",
    )

    stopping = threading.Event()

    def _shutdown(signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        log("info", "shutting down", signal=signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        server.board.store.close()
        log("info", "stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
