from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from .models import Resource, ResourceId

READ = 0b100
WRITE = 0b010
EXECUTE = 0b001

CERTGATE = 0o4000
SETGID = 0o2000
STICKY = 0o1000

type PermissionClass = Literal["owner", "group", "other"]
type PermissionBit = Literal["read", "write", "execute"]


def selected_class(
    resource: Resource,
    subject: ResourceId | None,
    memberships: Iterable[ResourceId],
) -> PermissionClass:
    """Select exactly one ordinary permission class; classes never accumulate."""
    if subject is not None and subject == resource.owner:
        return "owner"
    if resource.group in memberships:
        return "group"
    return "other"


def class_bits(mode: int, permission_class: PermissionClass) -> int:
    shift = {"owner": 6, "group": 3, "other": 0}[permission_class]
    return (mode >> shift) & 0b111


def allows(
    resource: Resource,
    subject: ResourceId | None,
    memberships: Iterable[ResourceId],
    permission: PermissionBit,
) -> bool:
    mask = {"read": READ, "write": WRITE, "execute": EXECUTE}[permission]
    cls = selected_class(resource, subject, memberships)
    return bool(class_bits(resource.mode, cls) & mask)


def has_certgate(mode: int) -> bool:
    return bool(mode & CERTGATE)


def has_setgid(mode: int) -> bool:
    return bool(mode & SETGID)


def has_sticky(mode: int) -> bool:
    return bool(mode & STICKY)


def inherit_group(parent: Resource, creator_primary_group: ResourceId) -> ResourceId:
    return parent.group if has_setgid(parent.mode) else creator_primary_group


def format_mode(mode: int) -> str:
    if not 0 <= mode <= 0o7777:
        raise ValueError("invalid_mode")
    return f"{mode:04o}"
