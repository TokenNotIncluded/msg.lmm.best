from __future__ import annotations

from dataclasses import dataclass, field

from .models import CapabilitySpec, OperationSpec, ResourceTypeSpec


class RegistryError(ValueError):
    pass


class RegistryFrozenError(RegistryError):
    pass


class RegistryConflictError(RegistryError):
    pass


class RegistryLookupError(RegistryError):
    pass


@dataclass(slots=True)
class Registry:
    _resource_types: dict[tuple[str, int], ResourceTypeSpec] = field(default_factory=dict)
    _capabilities: dict[tuple[str, int], CapabilitySpec] = field(default_factory=dict)
    _operations: dict[tuple[str, int], OperationSpec] = field(default_factory=dict)
    _frozen: bool = False

    def _assert_mutable(self) -> None:
        if self._frozen:
            raise RegistryFrozenError("registry_frozen")

    @staticmethod
    def _key(name: str, version: int) -> tuple[str, int]:
        if not name:
            raise RegistryError("empty_name")
        if version < 1:
            raise RegistryError("invalid_version")
        return name, version

    @staticmethod
    def _insert[T](
        target: dict[tuple[str, int], T],
        key: tuple[str, int],
        value: T,
        kind: str,
    ) -> None:
        if key in target:
            raise RegistryConflictError(f"duplicate_{kind}:{key[0]}@{key[1]}")
        target[key] = value

    def add_resource_type(self, spec: ResourceTypeSpec) -> None:
        self._assert_mutable()
        self._insert(
            self._resource_types,
            self._key(spec.name, spec.version),
            spec,
            "resource_type",
        )

    def add_capability(self, spec: CapabilitySpec) -> None:
        self._assert_mutable()
        self._insert(
            self._capabilities,
            self._key(spec.name, spec.version),
            spec,
            "capability",
        )

    def add_operation(self, spec: OperationSpec) -> None:
        self._assert_mutable()
        self._insert(
            self._operations,
            self._key(spec.name, spec.version),
            spec,
            "operation",
        )

    def freeze(self) -> None:
        self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    def resource_type(self, name: str, version: int) -> ResourceTypeSpec:
        try:
            return self._resource_types[self._key(name, version)]
        except KeyError as exc:
            raise RegistryLookupError(f"unknown_resource_type:{name}@{version}") from exc

    def capability(self, name: str, version: int) -> CapabilitySpec:
        try:
            return self._capabilities[self._key(name, version)]
        except KeyError as exc:
            raise RegistryLookupError(f"unknown_capability:{name}@{version}") from exc

    def operation(self, name: str, version: int) -> OperationSpec:
        try:
            return self._operations[self._key(name, version)]
        except KeyError as exc:
            raise RegistryLookupError(f"unknown_operation:{name}@{version}") from exc

    def capabilities(self) -> tuple[CapabilitySpec, ...]:
        return tuple(self._capabilities[key] for key in sorted(self._capabilities))

    def operations(self) -> tuple[OperationSpec, ...]:
        return tuple(self._operations[key] for key in sorted(self._operations))

    def resource_types(self) -> tuple[ResourceTypeSpec, ...]:
        return tuple(self._resource_types[key] for key in sorted(self._resource_types))
