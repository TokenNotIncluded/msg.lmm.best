"""Resource-scoped grants. Transport adapters must supply verified principals."""

import re
from dataclasses import dataclass

from msgnet.model import Denied, Invalid, identifier, integer


def resource(value: str) -> str:
    if value != "*" and not re.fullmatch(r"[a-z][a-z0-9.-]*:(?:[A-Za-z0-9_.-]+|\*)", value):
        raise Invalid("invalid resource scope")
    if value.endswith(":self"):
        raise Invalid("resolve self to the subject before entering the policy core")
    return value


@dataclass(frozen=True, slots=True)
class Grant:
    scope: str
    actions: frozenset[str]

    def __post_init__(self) -> None:
        resource(self.scope)
        if not self.actions:
            raise Invalid("empty action set")
        for action in self.actions:
            identifier(action)

    def covers(self, child: Grant) -> bool:
        scope_matches = (
            self.scope == "*"
            or self.scope == child.scope
            or (self.scope.endswith(":*") and child.scope.startswith(self.scope[:-1]))
        )
        return scope_matches and child.actions <= self.actions


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    grants: tuple[Grant, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.subject)

    def require(self, scope: str, action: str) -> None:
        requested = Grant(scope, frozenset({action}))
        if not any(grant.covers(requested) for grant in self.grants):
            raise Denied(f"missing {action} on {scope}")


@dataclass(frozen=True, slots=True)
class Authority:
    """An already signature/chain-verified certificate, not raw client claims."""

    serial: str
    subject: str
    grants: tuple[Grant, ...]
    not_before: int
    not_after: int
    depth_remaining: int = 0

    def __post_init__(self) -> None:
        identifier(self.serial)
        identifier(self.subject)
        integer(self.not_before)
        integer(self.not_after, minimum=self.not_before + 1)
        integer(self.depth_remaining, maximum=16)

    def active(self, now: int, revoked: frozenset[str]) -> bool:
        return self.serial not in revoked and self.not_before <= now < self.not_after

    def delegate(self, child: Authority, *, now: int, revoked: frozenset[str]) -> None:
        if not self.active(now, revoked) or self.depth_remaining < 1:
            raise Denied("issuer inactive or cannot delegate")
        if not self.not_before <= child.not_before < child.not_after <= self.not_after:
            raise Denied("delegation expands validity")
        if child.depth_remaining >= self.depth_remaining:
            raise Denied("delegation expands chain depth")
        if not all(any(parent.covers(grant) for parent in self.grants) for grant in child.grants):
            raise Denied("delegation expands authority")
