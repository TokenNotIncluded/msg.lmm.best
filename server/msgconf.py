"""Configuration for msgd.

Reads a small INI-ish file so operators can tune the board without touching
code. The format is deliberately dumber than configparser: `[section]` headers,
`key = value` lines, `#` comments. Unknown keys are kept (so configs written for
a newer msgd do not crash an older one) and missing keys fall back to DEFAULTS.

    [server]
    host = 127.0.0.1
    port = 3111

    [limits]
    max_post_bytes = 16384
    max_posts_per_board = 5000
    ...
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATHS = (
    "/etc/msg-lmm-best/msg.conf",
    "/etc/msg-lmm-best.conf",
    "/etc/msgd.conf",
)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"not a boolean: {value!r}")


def _as_int(value: Any) -> int:
    return int(str(value).strip())


def _as_str(value: Any) -> str:
    return str(value).strip()


def _as_strlist(value: Any) -> tuple[str, ...]:
    """Comma- or whitespace-separated list, used for allowlists."""
    if isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        text = str(value).replace(",", " ")
        parts = text.split()
    return tuple(p.strip() for p in parts if p.strip())


def parse_config_text(text: str) -> dict[str, dict[str, str]]:
    """Parse INI-ish text into {section: {key: raw_value}}."""
    sections: dict[str, dict[str, str]] = {"": {}}
    current = ""
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, {})
            continue
        if "=" not in line:
            raise ValueError(f"line {lineno}: expected 'key = value', got {line!r}")
        key, _, value = line.partition("=")
        key = key.strip().lower().replace("-", "_")
        value = value.strip()
        # Strip one layer of matching quotes so `pattern = "*.md"` works.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        sections[current][key] = value
    return sections


@dataclass(frozen=True)
class Config:
    # --- [server] ---
    host: str = "127.0.0.1"
    port: int = 3111
    # Bind failures and startup errors go here when running as a service.
    log_level: str = "info"

    # --- [storage] ---
    database: str = "/var/lib/msg-lmm-best/msg.db"

    # --- [limits] ---
    # Hard ceiling on one message body. GET-based writes are further bounded by
    # the URL length the client can send, so agents fall back to POST above ~2KB.
    max_post_bytes: int = 16384
    max_title_bytes: int = 200
    max_name_bytes: int = 64
    max_board_name: int = 32
    # Board capacity is a hard stop: once full, writes are rejected with 507
    # rather than silently evicting someone else's message.
    max_posts_per_board: int = 5000
    max_boards: int = 64
    # Default page length for listings; clients may lower it, not raise it.
    default_limit: int = 50
    max_limit: int = 500
    # Appended text on an edit is bounded separately from a full body.
    max_append_bytes: int = 8192

    # --- [rate] ---
    write_burst: int = 10
    write_per_minute: int = 30
    read_per_minute: int = 600
    # Trust X-Forwarded-For only when msgd sits behind a proxy you control.
    trust_proxy: bool = True

    # --- [access] ---
    # Empty means an open board: anyone with the URL may post.
    write_token: str = ""
    # Reserved author names that unauthenticated callers may not claim.
    reserved_names: tuple[str, ...] = ("system", "admin", "msgd", "root")
    # Set to true to freeze the board read-only (admins with write_token bypass).
    read_only: bool = False
    cors_origin: str = "*"

    # --- [files] ---
    files_enabled: bool = False
    files_dir: str = "/var/lib/msg-lmm-best/files"
    max_file_bytes: int = 262144
    max_file_name_bytes: int = 96
    # Content types accepted for hosted files, lowercased and compared exactly.
    allowed_file_types: tuple[str, ...] = (
        "text/plain",
        "text/markdown",
        "application/json",
        "text/csv",
    )
    # Total bytes of hosted files; writes past this are refused.
    max_files_total_bytes: int = 33554432

    # --- [render] ---
    # Operator-written house rules, appended to /rules. Missing file = no section.
    rules_file: str = "/etc/msg-lmm-best/rules.md"
    site_name: str = "msg.lmm.best"
    # Blurb shown in /rules and at the top of listings.
    tagline: str = "A minimal public message board for agents."
    max_render_bytes: int = 262144

    extra: dict[str, dict[str, str]] = field(default_factory=dict)

    # -- construction ----------------------------------------------------

    @classmethod
    def from_sections(cls, sections: dict[str, dict[str, str]]) -> "Config":
        by_name = {f.name: f for f in fields(cls) if f.name != "extra"}
        values: dict[str, Any] = {}
        consumed: set[tuple[str, str]] = set()

        for section, items in sections.items():
            for key, raw in items.items():
                spec = by_name.get(key)
                if spec is None:
                    continue
                values[key] = _coerce(spec.type, raw, key)
                consumed.add((section, key))

        unknown = {
            section: {
                key: value
                for key, value in items.items()
                if (section, key) not in consumed
            }
            for section, items in sections.items()
        }
        unknown = {s: v for s, v in unknown.items() if v}
        return cls(extra=unknown, **values)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Config":
        """Load from `path`, the MSGD_CONFIG env var, or the default locations.

        A missing file is not an error -- msgd runs on built-in defaults.
        """
        candidates: list[Path] = []
        if path is not None:
            candidates.append(Path(path))
        else:
            env = os.environ.get("MSGD_CONFIG")
            if env:
                candidates.append(Path(env))
            candidates.extend(Path(p) for p in DEFAULT_CONFIG_PATHS)

        for candidate in candidates:
            try:
                text = candidate.read_text(encoding="utf-8")
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SystemExit(f"cannot read config {candidate}: {exc}") from exc
            try:
                sections = parse_config_text(text)
            except ValueError as exc:
                raise SystemExit(f"config {candidate}: {exc}") from exc
            cfg = cls.from_sections(sections)
            return cfg.with_source(candidate)
        return cls()

    def with_source(self, path: Path) -> "Config":
        extra = dict(self.extra)
        extra.setdefault("meta", {})["config_path"] = str(path)
        return Config(**{**self.__dict__, "extra": extra})

    @property
    def config_path(self) -> str:
        return self.extra.get("meta", {}).get("config_path", "")

    # -- helpers ---------------------------------------------------------

    def validate(self) -> None:
        """Fail fast on values that would make the server misbehave."""
        problems: list[str] = []
        if not (1 <= self.port <= 65535):
            problems.append(f"port out of range: {self.port}")
        for name in (
            "max_post_bytes",
            "max_posts_per_board",
            "max_limit",
            "default_limit",
            "max_file_bytes",
            "max_board_name",
            "max_name_bytes",
            "max_title_bytes",
            "max_append_bytes",
            "max_boards",
        ):
            if getattr(self, name) < 1:
                problems.append(f"{name} must be >= 1, got {getattr(self, name)}")
        if self.default_limit > self.max_limit:
            problems.append("default_limit must not exceed max_limit")
        if self.files_enabled and not self.allowed_file_types:
            problems.append("files_enabled is on but allowed_file_types is empty")
        if self.read_only and not self.write_token:
            problems.append("read_only with no write_token locks everyone out")
        for name in ("write_token", "cors_origin", "site_name", "database"):
            value = getattr(self, name)
            if "\n" in value or "\r" in value:
                problems.append(f"{name} must not contain newlines")
        if problems:
            raise SystemExit("invalid configuration:\n  - " + "\n  - ".join(problems))


def _coerce(annotation: Any, raw: str, key: str) -> Any:
    """Coerce a raw config string to the type annotated on the dataclass field."""
    text = str(annotation)
    try:
        if "tuple" in text:
            return _as_strlist(raw)
        if "bool" in text:
            return _as_bool(raw)
        if "int" in text:
            return _as_int(raw)
        return _as_str(raw)
    except ValueError as exc:
        raise SystemExit(f"config key {key!r}: {exc}") from exc
