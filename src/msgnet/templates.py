"""Versioned, bounded field schemas without executable patterns or remote refs."""

from dataclasses import dataclass
from typing import Literal

from msgnet.model import Invalid, Json, Record, identifier, integer, text

type FieldKind = Literal["string", "integer", "boolean"]


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    kind: FieldKind
    required: bool = True
    maximum: int = 4096
    minimum: int = 0
    choices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.name)
        integer(self.minimum)
        integer(
            self.maximum,
            minimum=self.minimum,
            maximum=1_048_576 if self.kind == "string" else 10**12,
        )
        if self.kind not in ("string", "integer", "boolean"):
            raise Invalid("unsupported field type")
        if len(self.choices) > 64 or (self.choices and self.kind != "string"):
            raise Invalid("choices require a bounded string field")
        if any(not choice or len(choice) > self.maximum for choice in self.choices):
            raise Invalid("invalid choice")

    def validate(self, value: Json) -> None:
        if self.kind == "string":
            if not isinstance(value, str) or "\x00" in value or len(value) > self.maximum:
                raise Invalid(f"invalid string for {self.name}")
            result = value
            if len(result) < self.minimum or (self.choices and result not in self.choices):
                raise Invalid(f"invalid value for {self.name}")
        elif self.kind == "integer":
            integer(value, minimum=self.minimum, maximum=self.maximum)
        elif type(value) is not bool:
            raise Invalid(f"{self.name} must be boolean")


@dataclass(frozen=True, slots=True)
class Template:
    version: int
    fields: tuple[Field, ...]

    def __post_init__(self) -> None:
        integer(self.version, minimum=1)
        if len(self.fields) > 32 or len({field.name for field in self.fields}) != len(self.fields):
            raise Invalid("template has too many or duplicate fields")

    def validate(self, values: Record) -> None:
        allowed = {field.name for field in self.fields}
        if values.keys() - allowed:
            raise Invalid("unknown structured fields")
        for field in self.fields:
            if field.name not in values:
                if field.required:
                    raise Invalid(f"missing field: {field.name}")
            else:
                field.validate(values[field.name])

    def record(self) -> Record:
        fields: list[Json] = []
        for field in self.fields:
            choices: list[Json] = list(field.choices)
            fields.append({
                "name": field.name,
                "type": field.kind,
                "required": field.required,
                "min": field.minimum,
                "max": field.maximum,
                "choices": choices,
            })
        return {"version": self.version, "fields": fields}

    @classmethod
    def parse(cls, value: Record) -> Template:
        if value.keys() != {"version", "fields"} or not isinstance(value["fields"], list):
            raise Invalid("invalid template document")
        fields: list[Field] = []
        for item in value["fields"]:
            if not isinstance(item, dict) or item.keys() != {
                "name",
                "type",
                "required",
                "min",
                "max",
                "choices",
            }:
                raise Invalid("invalid template field")
            kind = item["type"]
            required = item["required"]
            choices = item["choices"]
            if kind not in ("string", "integer", "boolean") or not isinstance(kind, str):
                raise Invalid("unsupported field type")
            if not isinstance(required, bool) or not isinstance(choices, list):
                raise Invalid("invalid field options")
            match kind:
                case "string" | "integer" | "boolean":
                    fields.append(
                        Field(
                            text(item["name"]),
                            kind,
                            required,
                            integer(item["max"]),
                            integer(item["min"]),
                            tuple(text(choice) for choice in choices),
                        )
                    )
        return cls(integer(value["version"], minimum=1), tuple(fields))
