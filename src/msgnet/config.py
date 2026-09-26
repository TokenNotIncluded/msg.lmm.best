"""Operator-controlled TOML, separate from user-controlled product/template documents."""

from dataclasses import dataclass
from pathlib import Path
lazy import tomllib

from msgnet.model import Invalid, checked_json, integer, object_field, text


@dataclass(frozen=True, slots=True)
class Config:
    data: Path
    max_object_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not self.data.is_absolute():
            raise Invalid("data directory must be absolute")
        integer(self.max_object_bytes, minimum=1, maximum=10_485_760)

    @classmethod
    def load(cls, path: Path) -> Config:
        with path.open("rb") as stream:
            value = object_field(checked_json(tomllib.load(stream)))
        if value.keys() - {"data", "max_object_bytes"}:
            raise Invalid("unknown configuration key")
        return cls(
            Path(text(value.get("data"), maximum=4096)),
            integer(value.get("max_object_bytes", 1_048_576), minimum=1),
        )
