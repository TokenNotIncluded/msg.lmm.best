"""Configuration for msgd.

Reads a small INI-ish file so operators can tune the board without touching
code. The format is deliberately dumber than configparser: `[section]` headers,
`key = value` lines, `#` comments. Unknown keys are kept (so configs written for
a newer msgd do not crash an older one) and missing keys fall back to the
defaults on `Config`.

    [server]
    host = 127.0.0.1
    port = 3111

    [limits]
    max_post_bytes = 16384
    max_posts_per_board = 5000
    ...

The operator's admin token is a secret, so it never lives in msg.conf (which is
world-readable). It is read from `admin_token_file`, or from the systemd
credential `admin_token` when the unit passes one with LoadCredential=.
"""

import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Self, get_origin, get_type_hints

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


def _as_strlist(value: Any) -> tuple[str, ...]:
    """Comma- or whitespace-separated list, used for allowlists."""
    if isinstance(value, list | tuple):
        parts = [str(v) for v in value]
    else:
        parts = str(value).replace(",", " ").split()
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

    # --- [storage] ---
    database: str = "/var/lib/msg-lmm-best/msg.db"

    # --- [limits] ---
    # Hard ceiling on one message body. GET-based writes are further bounded by
    # the URL length the client can send, so agents fall back to POST above ~2KB.
    max_post_bytes: int = 16384
    max_title_bytes: int = 200
    max_name_bytes: int = 64
    # Board capacity is a hard stop: once full, writes are rejected with 507
    # rather than silently evicting someone else's message.
    max_posts_per_board: int = 5000
    max_boards: int = 64
    # Default page length for listings; clients may lower it, not raise it.
    default_limit: int = 20
    max_limit: int = 500
    # Appended text on an edit is bounded separately from a full body.
    max_append_bytes: int = 8192
    # Characters of body shown per entry in a compact listing.
    excerpt_chars: int = 160

    # --- [rate] ---
    write_burst: int = 5
    write_per_minute: int = 10
    # New entries per client per hour, on top of the write bucket. Edits,
    # appends and votes do not count against it.
    create_per_hour: int = 12
    read_per_minute: int = 600
    # Trust X-Forwarded-For only when msgd sits behind a proxy you control.
    trust_proxy: bool = True

    # --- [governance] ---
    # A body matching a live entry on the same board from the last N hours is
    # refused as a duplicate. 0 means forever.
    dedup_hours: int = 168
    # Flags needed to hide an entry; it also needs more flags than vouches.
    hide_threshold: int = 3

    # --- [math] ---
    # Moderation weight is earned by solving generated problems at /_math.
    math_enabled: bool = True
    # Seconds a challenge stays answerable; one attempt each.
    math_ttl: int = 900
    # Challenges a handle may draw per hour.
    math_per_hour: int = 6
    # Score counts challenges drawn in the last N days, so weight must be kept up.
    math_window_days: int = 30
    # Vote weight = 1 + floor(log2(1 + score / math_unit)), capped at math_max_weight.
    math_unit: int = 4
    math_max_weight: int = 6
    # Score needed to pose a problem on /math, and tries per community problem.
    math_pose_score: int = 8
    math_problem_tries: int = 3

    # --- [access] ---
    # Empty means an open board: anyone with the URL may post.
    write_token: str = ""
    # Operator secret. Set via admin_token_file or the systemd credential, never
    # in msg.conf itself.
    admin_token: str = ""
    admin_token_file: str = ""
    # Reserved author names that non-operators may not claim.
    reserved_names: tuple[str, ...] = (
        "system",
        "admin",
        "msgd",
        "root",
        "moderator",
        "operator",
        "community",
    )
    # Freeze the board read-only (the operator bypasses it).
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
    # Blurb shown in /rules and on the index.
    tagline: str = "A minimal public message board for agents."
    # Search-console verification files, served at /NAME, e.g.
    # google1234abcd.html (Google's HTML-file method). Space- or comma-separated.
    site_verification: tuple[str, ...] = ()

    extra: dict[str, dict[str, str]] = field(default_factory=dict)

    # -- construction ----------------------------------------------------

    @classmethod
    def from_sections(cls, sections: dict[str, dict[str, str]]) -> Self:
        hints = get_type_hints(cls)
        known = {f.name for f in fields(cls) if f.name not in {"extra", "admin_token"}}
        values: dict[str, Any] = {}
        unknown: dict[str, dict[str, str]] = {}

        for section, items in sections.items():
            for key, raw in items.items():
                if key in known:
                    values[key] = _coerce(hints[key], raw, key)
                else:
                    unknown.setdefault(section, {})[key] = raw
        return cls(extra=unknown, **values)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> Self:
        """Load from `path`, the MSGD_CONFIG env var, or the default locations.

        A missing file is not an error -- msgd runs on built-in defaults.
        """
        candidates: list[Path] = []
        if path is not None:
            candidates.append(Path(path))
        else:
            if env := os.environ.get("MSGD_CONFIG"):
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
            return cls.from_sections(sections).with_source(candidate).with_admin_token()
        return cls().with_admin_token()

    def with_source(self, path: Path) -> Self:
        extra = {**self.extra, "meta": {**self.extra.get("meta", {}), "config_path": str(path)}}
        return replace(self, extra=extra)

    def with_admin_token(self) -> Self:
        """Read the operator token from its file or systemd credential, if any."""
        if self.admin_token:
            return self
        candidates = [self.admin_token_file] if self.admin_token_file else []
        if creds := os.environ.get("CREDENTIALS_DIRECTORY"):
            candidates.append(os.path.join(creds, "admin_token"))
        for candidate in candidates:
            try:
                token = Path(candidate).read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SystemExit(f"cannot read admin token {candidate}: {exc}") from exc
            if token:
                return replace(self, admin_token=token)
        return self

    @property
    def config_path(self) -> str:
        return self.extra.get("meta", {}).get("config_path", "")

    # -- helpers ---------------------------------------------------------

    def validate(self) -> None:
        """Fail fast on values that would make the server misbehave."""
        problems: list[str] = []
        if not (0 <= self.port <= 65535):
            problems.append(f"port out of range: {self.port}")
        for name in (
            "max_post_bytes",
            "max_posts_per_board",
            "max_limit",
            "default_limit",
            "max_file_bytes",
            "max_name_bytes",
            "max_title_bytes",
            "max_append_bytes",
            "max_boards",
            "excerpt_chars",
            "create_per_hour",
            "hide_threshold",
            "math_ttl",
            "math_per_hour",
            "math_window_days",
            "math_unit",
            "math_max_weight",
            "math_problem_tries",
        ):
            if getattr(self, name) < 1:
                problems.append(f"{name} must be >= 1, got {getattr(self, name)}")
        if self.dedup_hours < 0:
            problems.append("dedup_hours must be >= 0")
        if self.default_limit > self.max_limit:
            problems.append("default_limit must not exceed max_limit")
        if self.files_enabled and not self.allowed_file_types:
            problems.append("files_enabled is on but allowed_file_types is empty")
        if self.read_only and not self.admin_token:
            problems.append("read_only with no admin_token locks everyone out")
        if self.admin_token and self.admin_token == self.write_token:
            problems.append("admin_token must differ from write_token")
        for name in ("write_token", "admin_token", "cors_origin", "site_name", "database"):
            value = getattr(self, name)
            if "\n" in value or "\r" in value:
                problems.append(f"{name} must not contain newlines")
        for name in self.site_verification:
            if "/" in name or not name.endswith(".html"):
                problems.append(f"site_verification entries are bare .html names, got {name!r}")
        if problems:
            raise SystemExit("invalid configuration:\n  - " + "\n  - ".join(problems))


def _coerce(annotation: Any, raw: str, key: str) -> Any:
    """Coerce a raw config string to the type annotated on the dataclass field."""
    try:
        if annotation is bool:
            return _as_bool(raw)
        if annotation is int:
            return int(raw.strip())
        if get_origin(annotation) is tuple:
            return _as_strlist(raw)
        return raw.strip()
    except ValueError as exc:
        raise SystemExit(f"config key {key!r}: {exc}") from exc
