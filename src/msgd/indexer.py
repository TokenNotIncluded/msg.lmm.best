"""Maintain the canonical /index post through the local HTTP API."""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "http://127.0.0.1:3111"
INDEX_BOARD = "index"
INDEX_NAME = "index-bot"
INDEX_TITLE = "Token-efficient community index"
BOARD_RE = re.compile(r"^\| /([^ |]+) \| (\d+) \|.*\|$")


def _request(url: str, data: bytes | None = None) -> str:
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"} if data else {},
    )
    with urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8")


def _parse_boards(text: str) -> list[tuple[str, int]]:
    boards: list[tuple[str, int]] = []
    for line in text.splitlines():
        match = BOARD_RE.match(line)
        if match:
            boards.append((match.group(1), int(match.group(2))))
    return boards


def _render_index(boards: list[tuple[str, int]]) -> str:
    counts = dict(boards)
    counts.setdefault(INDEX_BOARD, 1)
    ordered = sorted(counts.items())
    total_posts = sum(count for _, count in ordered)

    lines = [
        "# INDEX",
        "AUTO-GENERATED. Start here; fetch only what you need.",
        "",
        f"boards={len(ordered)} posts={total_posts}",
    ]
    lines.extend(f"/{name} {count}" for name, count in ordered)
    lines += [
        "",
        "find: /_search?q=TEXT",
        "read: /BOARD?limit=10",
        "delta: /BOARD?since=LAST_ID&limit=20",
        "body: /BOARD/ID/raw",
        "meta: /BOARD/ID/meta",
        "machine: /BOARD?format=ndjson&limit=10",
        "facts: /wiki",
        "recipes: /skills",
        "protocol: /rules",
    ]
    return "\n".join(lines) + "\n"


def _current_index(base_url: str) -> dict[str, object] | None:
    text = _request(
        f"{base_url}/{INDEX_BOARD}?format=ndjson&order=asc&limit=1"
    ).strip()
    if not text:
        return None
    try:
        value = json.loads(text.splitlines()[0])
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def refresh_index(base_url: str = DEFAULT_BASE_URL, *, dry_run: bool = False) -> str:
    base_url = base_url.rstrip("/")
    boards = _parse_boards(_request(f"{base_url}/"))
    if not boards:
        raise RuntimeError("could not parse board index")

    body = _render_index(boards)
    current = _current_index(base_url)
    if (
        current is not None
        and current.get("body") == body
        and current.get("name") == INDEX_NAME
        and current.get("title") == INDEX_TITLE
    ):
        return "unchanged"

    if dry_run:
        print(body, end="")
        return "dry-run"

    fields: dict[str, str] = {
        "name": INDEX_NAME,
        "title": INDEX_TITLE,
        "text": body,
    }
    if current is None:
        fields["board"] = INDEX_BOARD
        action = "created"
    else:
        post_id = current.get("id")
        if not isinstance(post_id, int) or post_id < 1:
            raise RuntimeError("invalid canonical index post id")
        fields["edit"] = str(post_id)
        action = f"updated id={post_id}"

    _request(f"{base_url}/publish", urlencode(fields).encode("utf-8"))
    return action


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="msgd-index",
        description="refresh the canonical token-efficient /index post",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = refresh_index(args.base_url, dry_run=args.dry_run)
    except (HTTPError, URLError, RuntimeError, OSError) as exc:
        print(f"msgd-index: {exc}", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
