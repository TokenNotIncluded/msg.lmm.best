from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from math import isfinite
from types import MappingProxyType
from typing import Literal, NewType

ResourceId = NewType("ResourceId", str)
RevisionId = NewType("RevisionId", str)
RequestId = NewType("RequestId", str)

type ID = str
type Digest = str
type Json = (
    None
    | bool
    | int
    | float
    | str
    | tuple[Json, ...]
    | Mapping[str, Json]
)
type JsonMap = Mapping[str, Json]
type Entry = Literal["network", "local_admin", "worker"]
type ResourceState = Literal["active", "archived", "purged"]
type ByteRange = tuple[int, int]


class ModelValidationError(ValueError):
    """Raised when data cannot participate in deterministic wire encoding."""


def freeze_json(value: object) -> Json:
    """Deep-copy JSON-compatible data into immutable deterministic containers."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ModelValidationError("non_finite_float")
        return value
    if isinstance(value, tuple | list):
        return tuple(freeze_json(item) for item in value)
    if isinstance(value, Mapping):
        frozen: dict[str, Json] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelValidationError("non_string_json_key")
            frozen[key] = freeze_json(item)
        return MappingProxyType(frozen)
    raise ModelValidationError(f"unsupported_json_type:{type(value).__name__}")


def validate_mode(mode: int) -> int:
    if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
        raise ModelValidationError("invalid_mode")
    return mode


def validate_byte_range(value: ByteRange) -> ByteRange:
    start, end = value
    if start < 0 or end < start:
        raise ModelValidationError("invalid_byte_range")
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class ResourceRef:
    id: ResourceId
    revision: RevisionId | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class BlobRef:
    digest: Digest
    size: int
    media_type: str

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ModelValidationError("negative_blob_size")
        if not self.digest:
            raise ModelValidationError("empty_digest")
        if not self.media_type:
            raise ModelValidationError("empty_media_type")


@dataclass(frozen=True, slots=True, kw_only=True)
class Resource:
    id: ResourceId
    type: str
    type_version: int
    name: str
    parent: ResourceId | None
    owner: ResourceId
    group: ResourceId
    mode: int
    generation: int
    revision: RevisionId | None
    state: ResourceState
    created_at: datetime
    created_by: ResourceId
    modified_at: datetime
    modified_by: ResourceId

    def __post_init__(self) -> None:
        validate_mode(self.mode)
        if self.type_version < 1:
            raise ModelValidationError("invalid_type_version")
        if self.generation < 0:
            raise ModelValidationError("negative_generation")
        for timestamp in (self.created_at, self.modified_at):
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ModelValidationError("naive_datetime")


@dataclass(frozen=True, slots=True, kw_only=True)
class Relation:
    type: str
    target: ResourceRef
    excerpt: ByteRange | None = None

    def __post_init__(self) -> None:
        if self.excerpt is not None:
            validate_byte_range(self.excerpt)


@dataclass(frozen=True, slots=True, kw_only=True)
class Signature:
    key_id: ID
    algorithm: str
    value: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class Revision:
    format_version: int
    id: RevisionId
    resource_id: ResourceId
    parents: tuple[RevisionId, ...]
    content: BlobRef
    relations: tuple[Relation, ...]
    actor: ResourceId
    subject: ResourceId
    author: ResourceId
    created_at: datetime
    manifest_digest: Digest
    signature: Signature | None = None

    def __post_init__(self) -> None:
        if self.format_version < 1:
            raise ModelValidationError("invalid_format_version")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ModelValidationError("naive_datetime")


@dataclass(frozen=True, slots=True, kw_only=True)
class Scope:
    resource_id: ResourceId
    descendants: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilityGrant:
    capability: str
    version: int
    scope: Scope
    operations: frozenset[str]
    constraints: JsonMap = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ModelValidationError("invalid_capability_version")
        object.__setattr__(self, "constraints", freeze_json(self.constraints))


@dataclass(frozen=True, slots=True, kw_only=True)
class ResourceTypeSpec:
    name: str
    version: int
    container: bool
    operations: frozenset[str]
    relations: frozenset[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilitySpec:
    name: str
    version: int
    scope_types: frozenset[str]
    operations: frozenset[str]
    replaces_checks: frozenset[str]
    delegatable: bool
    ca_only: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationSpec:
    name: str
    version: int
    effect: Literal["read", "transaction", "external"]
    entries: frozenset[Entry]
    require_signature: bool
