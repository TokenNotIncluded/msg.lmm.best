import pytest

from msgnet.model import Denied, Invalid, Record, decode, integer, usd_cents
from msgnet.policy import Authority, Grant
from msgnet.templates import Field, Template


@pytest.mark.parametrize("value,expected", [("0", 0), ("1", 100), ("1.2", 120), ("1.01", 101)])
def test_money_exact(value: str, expected: int) -> None:
    assert usd_cents(value) == expected


@pytest.mark.parametrize("value", [1.1, "NaN", "-1", ".1", "01", "1.001", "1e2", " 1.00"])
def test_money_rejects_ambiguous_values(value: object) -> None:
    with pytest.raises(Invalid):
        usd_cents(value)


def test_json_and_integer_boundaries() -> None:
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"[]", b"\xff"):
        with pytest.raises(Invalid):
            decode(raw)
    with pytest.raises(Invalid):
        integer(True)
    with pytest.raises(Invalid):
        decode(b'{"value":' + b"[" * 20 + b"0" + b"]" * 20 + b"}")


def test_template_closed_fields_and_round_trip() -> None:
    template = Template(
        1,
        (
            Field("kind", "string", choices=("code", "question")),
            Field("count", "integer", maximum=20),
        ),
    )
    template.validate({"kind": "code", "count": 3})
    assert Template.parse(template.record()) == template
    invalid_values: tuple[Record, ...] = (
        {"kind": "bad", "count": 1},
        {"kind": "code", "count": True},
        {"kind": "code", "count": 21},
        {"kind": "code", "count": 1, "admin": True},
    )
    for values in invalid_values:
        with pytest.raises(Invalid):
            template.validate(values)


def test_delegation_narrows_all_dimensions() -> None:
    parent = Authority(
        "p", "issuer", (Grant("topic:*", frozenset({"post.create", "post.edit"})),), 100, 1000, 2
    )
    child = Authority(
        "c", "subject", (Grant("topic:main", frozenset({"post.create"})),), 200, 900, 1
    )
    parent.delegate(child, now=300, revoked=frozenset())
    for bad in (
        Authority("c", "s", child.grants, 99, 900, 1),
        Authority("c", "s", child.grants, 200, 1001, 1),
        Authority("c", "s", child.grants, 200, 900, 2),
        Authority("c", "s", (Grant("topicx:main", frozenset({"post.create"})),), 200, 900, 1),
        Authority("c", "s", (Grant("topic:main", frozenset({"ca.issue"})),), 200, 900, 1),
    ):
        with pytest.raises(Denied):
            parent.delegate(bad, now=300, revoked=frozenset())
    with pytest.raises(Denied):
        parent.delegate(child, now=300, revoked=frozenset({"p"}))
    with pytest.raises(Denied):
        parent.delegate(child, now=1000, revoked=frozenset())
    with pytest.raises(Invalid):
        Grant("account:self", frozenset({"account.manage"}))


def test_optional_empty_string_respects_declared_minimum() -> None:
    Template(1, (Field("note", "string", minimum=0),)).validate({"note": ""})
    with pytest.raises(Invalid):
        Template(1, (Field("title", "string", minimum=1),)).validate({"title": ""})


def test_catalog_examples_are_schema_valid() -> None:
    from pathlib import Path

    from msgnet.model import object_field

    root = Path(__file__).parents[1] / "config"
    template = Template.parse(decode((root / "templates/store.json").read_bytes()))
    product = decode((root / "products/membership.json").read_bytes())
    template.validate(object_field(product["fields"]))
    assert object_field(product["fields"])["enabled"] is False
