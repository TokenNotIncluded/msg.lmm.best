from datetime import UTC, datetime

import pytest

from msg.core.models import (
    BlobRef,
    CapabilityGrant,
    ModelValidationError,
    Resource,
    ResourceId,
    Scope,
    freeze_json,
)


def test_freeze_json_recursively_copies_and_freezes() -> None:
    original = {"a": [1, {"b": True}]}
    frozen = freeze_json(original)
    original["a"].append(3)

    assert frozen["a"] == (1, {"b": True})
    with pytest.raises(TypeError):
        frozen["new"] = 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_freeze_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ModelValidationError, match="non_finite_float"):
        freeze_json(value)


def test_resource_requires_timezone_aware_timestamps() -> None:
    now = datetime.now(UTC)
    Resource(
        id=ResourceId("r1"),
        type="post",
        type_version=1,
        name="hello",
        parent=ResourceId("topic"),
        owner=ResourceId("u1"),
        group=ResourceId("public"),
        mode=0o644,
        generation=0,
        revision=None,
        state="active",
        created_at=now,
        created_by=ResourceId("u1"),
        modified_at=now,
        modified_by=ResourceId("u1"),
    )

    with pytest.raises(ModelValidationError, match="naive_datetime"):
        Resource(
            id=ResourceId("r2"),
            type="post",
            type_version=1,
            name="bad",
            parent=None,
            owner=ResourceId("u1"),
            group=ResourceId("public"),
            mode=0o644,
            generation=0,
            revision=None,
            state="active",
            created_at=datetime(2026, 1, 1),
            created_by=ResourceId("u1"),
            modified_at=now,
            modified_by=ResourceId("u1"),
        )


def test_blob_ref_rejects_negative_size() -> None:
    with pytest.raises(ModelValidationError, match="negative_blob_size"):
        BlobRef(digest="sha256:x", size=-1, media_type="text/plain")


def test_capability_constraints_are_frozen() -> None:
    grant = CapabilityGrant(
        capability="resource.certified_write",
        version=1,
        scope=Scope(resource_id=ResourceId("r1")),
        operations=frozenset({"content.post_create@1"}),
        constraints={"x": [1, 2]},
    )
    assert grant.constraints["x"] == (1, 2)
