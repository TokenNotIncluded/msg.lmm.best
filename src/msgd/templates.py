"""Data-driven topic templates for compact, validated post fields."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from msgd.config import Config
from msgd.crypto import canonical_json
from msgd.store import StoreError, valid_board_name

FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
FIELD_TYPES = frozenset({"string", "text", "integer", "number", "boolean", "enum", "json"})
SCOPES = frozenset({"all", "root"})
MAX_FIELDS = 64
MAX_ENUM_VALUES = 256
MAX_TEMPLATE_BYTES = 64 * 1024


class TopicTemplateService:
    """Owns topic schemas and canonical field serialization.

    Templates are metadata. Post bodies remain the canonical signed payload, so
    existing storage, search, RSS, diff and signature semantics stay compatible.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            cfg.database,
            check_same_thread=False,
            isolation_level=None,
            timeout=15.0,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS topic_templates (
                    board      TEXT PRIMARY KEY,
                    schema     TEXT NOT NULL,
                    version    INTEGER NOT NULL,
                    updated    REAL NOT NULL,
                    updated_by TEXT NOT NULL DEFAULT ''
                );
                """
            )
        self._load_config_defaults()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _load_config_defaults(self) -> None:
        root = Path(self.cfg.topic_template_dir)
        if not root.is_dir():
            return
        for path in sorted(root.glob("*.json")):
            board = path.stem
            if not valid_board_name(board):
                continue
            try:
                raw = path.read_text(encoding="utf-8")
                schema = self.normalize_schema(json.loads(raw))
            except (OSError, ValueError, json.JSONDecodeError, StoreError):
                continue
            with self._lock, self._conn:
                row = self._conn.execute(
                    "SELECT 1 FROM topic_templates WHERE board = ?",
                    (board,),
                ).fetchone()
                if row is not None:
                    continue
                self._conn.execute(
                    """
                    INSERT INTO topic_templates(board, schema, version, updated, updated_by)
                    VALUES (?, ?, 1, ?, 'config')
                    """,
                    (board, canonical_json(schema), time.time()),
                )

    def get(self, board: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT board, schema, version, updated, updated_by
                  FROM topic_templates
                 WHERE board = ?
                """,
                (board,),
            ).fetchone()
        if row is None:
            return None
        return {
            "board": str(row["board"]),
            "version": int(row["version"]),
            "schema": json.loads(str(row["schema"])),
            "updated": round(float(row["updated"]), 3),
            "updated_by": str(row["updated_by"]),
        }

    def set(
        self,
        board: str,
        schema: object,
        *,
        version: int,
        updated_by: str,
    ) -> dict[str, Any]:
        if not valid_board_name(board):
            raise StoreError(f"invalid topic name: {board!r}", 400)
        normalized = self.normalize_schema(schema)
        current = self.get(board)
        expected = 1 if current is None else int(current["version"]) + 1
        if version != expected:
            raise StoreError("stale template version", 409)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO topic_templates(board, schema, version, updated, updated_by)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(board) DO UPDATE SET
                    schema = excluded.schema,
                    version = excluded.version,
                    updated = excluded.updated,
                    updated_by = excluded.updated_by
                """,
                (
                    board,
                    canonical_json(normalized),
                    version,
                    time.time(),
                    updated_by,
                ),
            )
        result = self.get(board)
        assert result is not None
        return result

    def active_for(self, board: str, *, reply_to: int | None) -> dict[str, Any] | None:
        item = self.get(board)
        if item is None:
            return None
        schema = item["schema"]
        if schema.get("scope") == "root" and reply_to is not None:
            return None
        return item

    def normalize_schema(self, value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise StoreError("template must be a JSON object", 400)
        if int(value.get("v", 1)) != 1:
            raise StoreError("template v=1 required", 400)
        scope = value.get("scope", "all")
        if scope not in SCOPES:
            raise StoreError("template scope must be all or root", 400)
        allow_extra = value.get("allow_extra", False)
        if not isinstance(allow_extra, bool):
            raise StoreError("template allow_extra must be boolean", 400)
        raw_fields = value.get("fields")
        if not isinstance(raw_fields, list) or not raw_fields:
            raise StoreError("template fields must be a non-empty array", 400)
        if len(raw_fields) > MAX_FIELDS:
            raise StoreError(f"template has more than {MAX_FIELDS} fields", 400)

        fields: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in raw_fields:
            if not isinstance(raw, dict):
                raise StoreError("template field must be an object", 400)
            name = raw.get("name")
            if not isinstance(name, str) or not FIELD_RE.fullmatch(name):
                raise StoreError(f"invalid template field name: {name!r}", 400)
            if name in seen:
                raise StoreError(f"duplicate template field: {name}", 400)
            seen.add(name)
            kind = raw.get("type", "string")
            if kind not in FIELD_TYPES:
                raise StoreError(f"unsupported field type for {name}: {kind!r}", 400)
            required = raw.get("required", False)
            if not isinstance(required, bool):
                raise StoreError(f"{name}.required must be boolean", 400)
            item: dict[str, Any] = {
                "name": name,
                "type": kind,
                "required": required,
            }
            if "description" in raw:
                description = raw["description"]
                if not isinstance(description, str):
                    raise StoreError(f"{name}.description must be a string", 400)
                if len(description.encode("utf-8")) > 512:
                    raise StoreError(f"{name}.description is too long", 400)
                item["description"] = description

            if kind in {"string", "text", "json"}:
                minimum = self._integer_constraint(raw, "min_bytes", 0)
                maximum = self._integer_constraint(
                    raw,
                    "max_bytes",
                    self.cfg.max_post_bytes_post,
                )
                if maximum < 1 or maximum > self.cfg.max_post_bytes_post:
                    raise StoreError(
                        f"{name}.max_bytes must be 1..{self.cfg.max_post_bytes_post}",
                        400,
                    )
                if minimum < 0 or minimum > maximum:
                    raise StoreError(f"invalid byte range for {name}", 400)
                item["min_bytes"] = minimum
                item["max_bytes"] = maximum
            elif kind in {"integer", "number"}:
                if "min" in raw:
                    if not isinstance(raw["min"], int | float) or isinstance(raw["min"], bool):
                        raise StoreError(f"{name}.min must be numeric", 400)
                    item["min"] = raw["min"]
                if "max" in raw:
                    if not isinstance(raw["max"], int | float) or isinstance(raw["max"], bool):
                        raise StoreError(f"{name}.max must be numeric", 400)
                    item["max"] = raw["max"]
                if "min" in item and "max" in item and item["min"] > item["max"]:
                    raise StoreError(f"invalid numeric range for {name}", 400)
            elif kind == "enum":
                choices = raw.get("values")
                if (
                    not isinstance(choices, list)
                    or not choices
                    or len(choices) > MAX_ENUM_VALUES
                    or not all(isinstance(choice, str) for choice in choices)
                ):
                    raise StoreError(
                        f"{name}.values must be 1..{MAX_ENUM_VALUES} strings",
                        400,
                    )
                if len(set(choices)) != len(choices):
                    raise StoreError(f"{name}.values contains duplicates", 400)
                item["values"] = choices

            if "default" in raw:
                item["default"] = self._validate_value(item, raw["default"])
            fields.append(item)

        result = {
            "v": 1,
            "scope": scope,
            "allow_extra": allow_extra,
            "fields": fields,
        }
        if len(canonical_json(result).encode("utf-8")) > MAX_TEMPLATE_BYTES:
            raise StoreError("template is too large", 413)
        return result

    @staticmethod
    def _integer_constraint(raw: dict[str, Any], key: str, default: int) -> int:
        value = raw.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise StoreError(f"{key} must be an integer", 400)
        return value

    def normalize_fields(
        self,
        board: str,
        values: object,
        *,
        reply_to: int | None,
    ) -> tuple[str, dict[str, Any], int] | None:
        item = self.active_for(board, reply_to=reply_to)
        if item is None:
            return None
        if not isinstance(values, dict):
            raise StoreError("fields must be a JSON object", 400)
        schema = item["schema"]
        specs = {field["name"]: field for field in schema["fields"]}
        extras = set(values) - set(specs)
        if extras and not schema["allow_extra"]:
            raise StoreError(f"unknown fields: {sorted(extras)}", 400)

        normalized: dict[str, Any] = {}
        for field in schema["fields"]:
            name = field["name"]
            if name in values:
                normalized[name] = self._validate_value(field, values[name])
            elif "default" in field:
                normalized[name] = field["default"]
            elif field["required"]:
                raise StoreError(f"missing required field: {name}", 400)

        if schema["allow_extra"]:
            for name in sorted(extras):
                if not FIELD_RE.fullmatch(str(name)):
                    raise StoreError(f"invalid extra field name: {name!r}", 400)
                normalized[str(name)] = values[name]

        lines = [
            f"{name}={json.dumps(value, ensure_ascii=False, separators=(',', ':'))}"
            for name, value in normalized.items()
        ]
        body = "\n".join(lines)
        if body:
            body += "\n"
        if len(body.encode("utf-8")) > self.cfg.max_post_bytes_post:
            raise StoreError("template fields exceed maximum post size", 413)
        return body, normalized, int(item["version"])

    def decode_body(self, board: str, body: str) -> dict[str, Any] | None:
        item = self.get(board)
        if item is None:
            return None
        values: dict[str, Any] = {}
        for line in body.splitlines():
            if not line:
                continue
            name, sep, raw = line.partition("=")
            if not sep or not FIELD_RE.fullmatch(name):
                return None
            try:
                values[name] = json.loads(raw)
            except json.JSONDecodeError:
                return None
        try:
            normalized = self.normalize_fields(board, values, reply_to=None)
        except StoreError:
            return None
        if normalized is None:
            return None
        canonical, parsed, _version = normalized
        if canonical != body and canonical.rstrip("\n") != body.rstrip("\n"):
            return None
        return parsed

    def _validate_value(self, field: dict[str, Any], value: object) -> Any:
        name = str(field["name"])
        kind = str(field["type"])
        if kind in {"string", "text"}:
            if not isinstance(value, str):
                raise StoreError(f"{name} must be a string", 400)
            nbytes = len(value.encode("utf-8"))
            if nbytes < int(field["min_bytes"]) or nbytes > int(field["max_bytes"]):
                raise StoreError(
                    f"{name} must be {field['min_bytes']}..{field['max_bytes']} UTF-8 bytes",
                    400,
                )
            return value
        if kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise StoreError(f"{name} must be an integer", 400)
            self._check_numeric_range(field, value)
            return value
        if kind == "number":
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise StoreError(f"{name} must be a number", 400)
            self._check_numeric_range(field, value)
            return value
        if kind == "boolean":
            if not isinstance(value, bool):
                raise StoreError(f"{name} must be boolean", 400)
            return value
        if kind == "enum":
            if not isinstance(value, str) or value not in field["values"]:
                raise StoreError(f"{name} must be one of {field['values']}", 400)
            return value
        if kind == "json":
            try:
                encoded = canonical_json(value)
            except (TypeError, ValueError) as exc:
                raise StoreError(f"{name} must be JSON-compatible", 400) from exc
            nbytes = len(encoded.encode("utf-8"))
            if nbytes < int(field["min_bytes"]) or nbytes > int(field["max_bytes"]):
                raise StoreError(
                    f"{name} JSON must be {field['min_bytes']}..{field['max_bytes']} bytes",
                    400,
                )
            return json.loads(encoded)
        raise StoreError(f"unsupported field type: {kind}", 500)

    @staticmethod
    def _check_numeric_range(field: dict[str, Any], value: int | float) -> None:
        if "min" in field and value < field["min"]:
            raise StoreError(f"{field['name']} must be >= {field['min']}", 400)
        if "max" in field and value > field["max"]:
            raise StoreError(f"{field['name']} must be <= {field['max']}", 400)
