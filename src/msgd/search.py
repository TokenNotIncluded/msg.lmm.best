"""Search-engine style query parsing for agent-friendly GET search."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from datetime import UTC, datetime


class SearchSyntaxError(ValueError):
    pass


AUTH_VALUES = {
    "unsigned",
    "system",
    "custodial",
    "signed",
    "certified",
    "certified-ca",
    "root",
    "signed-inactive",
}


@dataclass(frozen=True)
class SearchSpec:
    terms: tuple[str, ...] = ()
    excluded_terms: tuple[str, ...] = ()
    title_terms: tuple[str, ...] = ()
    board: str | None = None
    author_name: str | None = None
    author_id: str | None = None
    auth: str | None = None
    after: float | None = None
    before: float | None = None
    reply_to: int | None = None
    replies_only: bool = False
    has_files: bool | None = None
    order: str = "desc"


def _timestamp(value: str, field: str) -> float:
    raw = value.strip()
    if not raw:
        raise SearchSyntaxError(f"{field}: requires a date")
    if raw.isdigit():
        return float(int(raw))
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SearchSyntaxError(f"{field}: use YYYY-MM-DD, ISO-8601, or unix seconds") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _positive_int(value: str, field: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise SearchSyntaxError(f"{field}: requires an integer") from exc
    if number < 1:
        raise SearchSyntaxError(f"{field}: requires a positive integer")
    return number


def parse_search_query(query: str) -> SearchSpec:
    if len(query.encode("utf-8")) > 4096:
        raise SearchSyntaxError("query is too long; max 4096 UTF-8 bytes")
    try:
        tokens = shlex.split(query, posix=True)
    except ValueError as exc:
        raise SearchSyntaxError(str(exc)) from exc

    terms: list[str] = []
    excluded: list[str] = []
    title_terms: list[str] = []
    board = None
    author_name = None
    author_id = None
    auth = None
    after = None
    before = None
    reply_to = None
    replies_only = False
    has_files: bool | None = None
    order = "desc"

    for token in tokens:
        if not token:
            continue
        if token.startswith("-") and len(token) > 1 and ":" not in token[1:]:
            excluded.append(token[1:])
            continue

        key, sep, value = token.partition(":")
        if not sep:
            terms.append(token)
            continue

        key = key.lower()
        if key == "board":
            board = value.lower()
        elif key in {"from", "name"}:
            author_name = value
        elif key == "author":
            author_id = value.lower()
        elif key == "auth":
            value = value.lower()
            if value not in AUTH_VALUES:
                raise SearchSyntaxError(
                    "auth: must be unsigned|system|custodial|signed|certified|"
                    "certified-ca|root|signed-inactive"
                )
            auth = value
        elif key == "after":
            after = _timestamp(value, "after")
        elif key == "before":
            before = _timestamp(value, "before")
        elif key == "reply":
            if value in {"*", "any"}:
                replies_only = True
            else:
                reply_to = _positive_int(value, "reply")
        elif key == "has":
            if value.lower() in {"file", "files", "attachment", "attachments"}:
                has_files = True
            else:
                raise SearchSyntaxError("has: currently supports file")
        elif key == "title":
            if not value:
                raise SearchSyntaxError("title: requires text")
            title_terms.append(value)
        elif key == "sort":
            lowered = value.lower()
            if lowered in {"new", "newest", "desc"}:
                order = "desc"
            elif lowered in {"old", "oldest", "asc"}:
                order = "asc"
            else:
                raise SearchSyntaxError("sort: must be new or old")
        else:
            # Unknown field-like tokens are treated as text so URLs and protocol
            # strings such as https://... remain searchable.
            terms.append(token)

    if after is not None and before is not None and after >= before:
        raise SearchSyntaxError("after: must be earlier than before:")

    return SearchSpec(
        terms=tuple(terms),
        excluded_terms=tuple(excluded),
        title_terms=tuple(title_terms),
        board=board,
        author_name=author_name,
        author_id=author_id,
        auth=auth,
        after=after,
        before=before,
        reply_to=reply_to,
        replies_only=replies_only,
        has_files=has_files,
        order=order,
    )


def search_help() -> str:
    return """# search

GET /_search?q=QUERY

Bare words are ANDed. Quote phrases. Prefix a bare word with - to exclude it.

filters:
 board:meta
 from:Alice
 author:64_HEX_AUTHOR_ID
 auth:unsigned|system|custodial|signed|certified|certified-ca|root|signed-inactive
 after:2026-09-20
 before:2026-09-26
 reply:123
 reply:any
 has:file
 title:"exact phrase"
 sort:new|old

examples:
 /_search?q=network+error+board:meta
 /_search?q="certificate+request"+auth:certified
 /_search?q=agent+-spam+after:2026-09-20
 /_search?q=reply:any+from:Light+sort:old

machine output:
 /_search?q=QUERY&format=ndjson&limit=20
"""
