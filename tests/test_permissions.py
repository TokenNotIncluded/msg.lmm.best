from datetime import UTC, datetime

from msg.core.models import Resource, ResourceId
from msg.core.permissions import (
    allows,
    format_mode,
    has_certgate,
    has_setgid,
    has_sticky,
    inherit_group,
    selected_class,
)


def resource(mode: int, *, owner: str = "alice", group: str = "staff") -> Resource:
    now = datetime.now(UTC)
    return Resource(
        id=ResourceId("r"),
        type="topic",
        type_version=1,
        name="x",
        parent=None,
        owner=ResourceId(owner),
        group=ResourceId(group),
        mode=mode,
        generation=0,
        revision=None,
        state="active",
        created_at=now,
        created_by=ResourceId(owner),
        modified_at=now,
        modified_by=ResourceId(owner),
    )


def test_owner_bits_do_not_accumulate_with_group_or_other() -> None:
    item = resource(0o406)
    assert selected_class(item, ResourceId("alice"), [ResourceId("staff")]) == "owner"
    assert not allows(item, ResourceId("alice"), [ResourceId("staff")], "write")


def test_group_selected_before_other() -> None:
    item = resource(0o604)
    assert selected_class(item, ResourceId("bob"), [ResourceId("staff")]) == "group"
    assert not allows(item, ResourceId("bob"), [ResourceId("staff")], "read")


def test_other_for_anonymous_reader() -> None:
    item = resource(0o004)
    assert allows(item, None, [], "read")


def test_special_bits_are_independent() -> None:
    assert has_certgate(0o5777)
    assert not has_setgid(0o5777)
    assert has_sticky(0o5777)
    assert has_setgid(0o2770)


def test_setgid_controls_group_inheritance() -> None:
    assert inherit_group(resource(0o2770), ResourceId("users")) == ResourceId("staff")
    assert inherit_group(resource(0o0770), ResourceId("users")) == ResourceId("users")


def test_mode_is_rendered_as_four_octals() -> None:
    assert format_mode(0o700) == "0700"
    assert format_mode(0o5777) == "5777"
