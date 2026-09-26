from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from .models import Json, ModelValidationError, freeze_json

type FieldType = Literal["str", "text", "int", "bool", "enum", "ref", "file"]

_HEADER_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_.-]*)@(?P<version>[1-9][0-9]*)$")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")


class TemplateSyntaxError(ValueError):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class FieldSpec:
    name: str
    type: FieldType
    required: bool
    default: Json | None
    has_default: bool
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class TemplateDefinition:
    name: str
    version: int
    fields: tuple[FieldSpec, ...]


def _parse_type(raw: str) -> tuple[FieldType, tuple[str, ...]]:
    if raw.startswith("enum(") and raw.endswith(")"):
        values = tuple(part.strip() for part in raw[5:-1].split(","))
        if not values or any(not value for value in values) or len(set(values)) != len(values):
            raise TemplateSyntaxError("invalid_enum")
        return "enum", values
    if raw not in {"str", "text", "int", "bool", "ref", "file"}:
        raise TemplateSyntaxError(f"unknown_field_type:{raw}")
    return raw, ()


def _parse_default(raw: str, field_type: FieldType, choices: tuple[str, ...]) -> Json:
    if field_type in {"str", "text", "ref", "file", "enum"}:
        value: Json = raw
    elif field_type == "int":
        try:
            value = int(raw)
        except ValueError as exc:
            raise TemplateSyntaxError("invalid_int_default") from exc
    elif field_type == "bool":
        if raw not in {"true", "false"}:
            raise TemplateSyntaxError("invalid_bool_default")
        value = raw == "true"
    else:
        raise AssertionError(field_type)
    if field_type == "enum" and value not in choices:
        raise TemplateSyntaxError("enum_default_not_in_choices")
    try:
        return freeze_json(value)
    except ModelValidationError as exc:
        raise TemplateSyntaxError(str(exc)) from exc


def parse_template(source: str) -> TemplateDefinition:
    lines = [
        line.strip()
        for line in source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        raise TemplateSyntaxError("empty_template")

    match = _HEADER_RE.fullmatch(lines[0])
    if match is None:
        raise TemplateSyntaxError("invalid_header")

    seen: set[str] = set()
    fields: list[FieldSpec] = []

    for line in lines[1:]:
        if ":" not in line:
            raise TemplateSyntaxError("missing_field_type")
        name, tail = line.split(":", 1)
        if not _FIELD_NAME_RE.fullmatch(name):
            raise TemplateSyntaxError(f"invalid_field_name:{name}")
        if name in seen:
            raise TemplateSyntaxError(f"duplicate_field:{name}")
        seen.add(name)

        required = False
        has_default = False
        default: Json | None = None

        if tail.endswith("!"):
            required = True
            tail = tail[:-1]
        elif tail.endswith("?"):
            tail = tail[:-1]

        if "=" in tail:
            if required:
                raise TemplateSyntaxError("required_field_has_default")
            type_text, raw_default = tail.split("=", 1)
            if not raw_default:
                raise TemplateSyntaxError("empty_default")
            has_default = True
        else:
            type_text = tail
            raw_default = ""

        field_type, choices = _parse_type(type_text)
        if has_default:
            default = _parse_default(raw_default, field_type, choices)

        fields.append(
            FieldSpec(
                name=name,
                type=field_type,
                required=required,
                default=default,
                has_default=has_default,
                choices=choices,
            )
        )

    return TemplateDefinition(
        name=match.group("name"),
        version=int(match.group("version")),
        fields=tuple(fields),
    )


def normalize_values(
    template: TemplateDefinition,
    values: dict[str, object],
) -> dict[str, Json]:
    specs = {field.name: field for field in template.fields}
    unknown = set(values) - set(specs)
    if unknown:
        raise TemplateSyntaxError(f"unknown_field:{sorted(unknown)[0]}")

    normalized: dict[str, Json] = {}
    for spec in template.fields:
        if spec.name in values:
            value = freeze_json(values[spec.name])
        elif spec.has_default:
            value = spec.default
        elif spec.required:
            raise TemplateSyntaxError(f"missing_required:{spec.name}")
        else:
            continue

        if spec.type == "int" and (not isinstance(value, int) or isinstance(value, bool)):
            raise TemplateSyntaxError(f"type_error:{spec.name}")
        if spec.type == "bool" and not isinstance(value, bool):
            raise TemplateSyntaxError(f"type_error:{spec.name}")
        if spec.type in {"str", "text", "ref", "file", "enum"} and not isinstance(value, str):
            raise TemplateSyntaxError(f"type_error:{spec.name}")
        if spec.type == "enum" and value not in spec.choices:
            raise TemplateSyntaxError(f"enum_value:{spec.name}")
        normalized[spec.name] = value
    return normalized


def canonical_values_json(values: dict[str, Json]) -> bytes:
    return json.dumps(
        values,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
