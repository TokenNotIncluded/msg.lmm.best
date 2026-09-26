"""Validated boundary values. JSON decoding is not domain validation."""

import json
import math
import re
from collections.abc import Mapping

type Json = bool | int | float | str | list[Json] | dict[str, Json] | None
type Record = dict[str, Json]
MAX_CENTS = 10**12


class Invalid(ValueError):
    """A caller-supplied value violates a domain invariant."""


class NotFound(Invalid):
    """A requested resource does not exist or is not publicly visible."""


class Conflict(Invalid):
    """An idempotency key or optimistic revision no longer matches."""


class Denied(Invalid):
    """The verified principal lacks the requested capability."""


def checked_json(value: object, *, depth: int = 0) -> Json:
    if depth > 16:
        raise Invalid("JSON nesting exceeds 16")
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, list):
        return [checked_json(item, depth=depth + 1) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {str(key): checked_json(item, depth=depth + 1) for key, item in value.items()}
    raise Invalid("expected finite JSON values and string object keys")


def _pairs(pairs: list[tuple[str, Json]]) -> Record:
    result: Record = {}
    for key, value in pairs:
        if key in result:
            raise Invalid(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(raw: bytes, *, limit: int = 1_048_576) -> Record:
    if len(raw) > limit:
        raise Invalid("JSON payload exceeds limit")
    try:
        value: object = json.loads(raw, object_pairs_hook=_pairs)
        parsed = checked_json(value)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid("invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise Invalid("expected JSON object")
    return parsed


def encode(value: Mapping[str, Json]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def text(value: object, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise Invalid(f"expected nonempty text of at most {maximum} characters")
    return value


def integer(value: object, *, minimum: int = 0, maximum: int = MAX_CENTS) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise Invalid(f"expected integer in [{minimum}, {maximum}]")
    return value


def identifier(value: object) -> str:
    result = text(value, maximum=128)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", result):
        raise Invalid("invalid identifier")
    return result


def usd_cents(value: object) -> int:
    """Parse a display amount exactly; never round or accept a binary float."""
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9]\d{0,10})(?:\.\d{1,2})?", value):
        raise Invalid("expected a nonnegative USD decimal string, at most two decimals")
    whole, _, fraction = value.partition(".")
    return integer(int(whole) * 100 + int(fraction.ljust(2, "0")))


def object_field(value: Json) -> Record:
    if not isinstance(value, dict):
        raise Invalid("expected object")
    return value
