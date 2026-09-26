import pytest

from msg.core.models import CapabilitySpec, OperationSpec, ResourceTypeSpec
from msg.core.registry import (
    Registry,
    RegistryConflictError,
    RegistryFrozenError,
    RegistryLookupError,
)


def test_registry_rejects_duplicate_capabilities() -> None:
    registry = Registry()
    spec = CapabilitySpec(
        name="tool.use",
        version=1,
        scope_types=frozenset({"tool"}),
        operations=frozenset({"tool.invoke@1"}),
        replaces_checks=frozenset({"tool_use"}),
        delegatable=True,
        ca_only=False,
    )
    registry.add_capability(spec)

    with pytest.raises(RegistryConflictError, match="duplicate_capability"):
        registry.add_capability(spec)


def test_frozen_registry_rejects_mutation() -> None:
    registry = Registry()
    registry.freeze()
    with pytest.raises(RegistryFrozenError, match="registry_frozen"):
        registry.add_resource_type(
            ResourceTypeSpec(
                name="post",
                version=1,
                container=False,
                operations=frozenset(),
                relations=frozenset(),
            )
        )


def test_lookup_is_exact_by_version() -> None:
    registry = Registry()
    registry.add_operation(
        OperationSpec(
            name="content.post_create",
            version=1,
            effect="transaction",
            entries=frozenset({"network"}),
            require_signature=True,
        )
    )

    assert registry.operation("content.post_create", 1).effect == "transaction"
    with pytest.raises(RegistryLookupError, match="unknown_operation"):
        registry.operation("content.post_create", 2)


def test_registry_listing_is_deterministic() -> None:
    registry = Registry()
    for name in ["zeta", "alpha"]:
        registry.add_capability(
            CapabilitySpec(
                name=name,
                version=1,
                scope_types=frozenset(),
                operations=frozenset(),
                replaces_checks=frozenset(),
                delegatable=False,
                ca_only=False,
            )
        )
    assert [item.name for item in registry.capabilities()] == ["alpha", "zeta"]
