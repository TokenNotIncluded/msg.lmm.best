import pytest

from msg.core.template_dsl import (
    TemplateSyntaxError,
    canonical_values_json,
    normalize_values,
    parse_template,
)


def test_parse_small_template_dsl() -> None:
    template = parse_template(
        """
        message@1
        to:ref!
        body:text!
        urgent:bool=false
        context:ref?
        role:enum(user,assistant)=user
        """
    )

    assert template.name == "message"
    assert template.version == 1
    assert [field.name for field in template.fields] == [
        "to",
        "body",
        "urgent",
        "context",
        "role",
    ]
    assert template.fields[-1].choices == ("user", "assistant")


def test_duplicate_fields_are_rejected() -> None:
    with pytest.raises(TemplateSyntaxError, match="duplicate_field"):
        parse_template("x@1\na:str?\na:text?")


def test_required_field_cannot_have_default() -> None:
    with pytest.raises(TemplateSyntaxError, match="required_field_has_default"):
        parse_template("x@1\na:str=hello!")


def test_normalization_applies_defaults_but_omits_optional_missing_values() -> None:
    template = parse_template(
        "message@1\nto:ref!\nbody:text!\nurgent:bool=false\ncontext:ref?"
    )
    normalized = normalize_values(template, {"to": "u1", "body": "hello"})
    assert normalized == {"to": "u1", "body": "hello", "urgent": False}


def test_normalization_rejects_unknown_fields() -> None:
    template = parse_template("x@1\na:str?")
    with pytest.raises(TemplateSyntaxError, match="unknown_field:b"):
        normalize_values(template, {"b": "x"})


def test_normalization_rejects_enum_outside_choices() -> None:
    template = parse_template("x@1\nrole:enum(user,assistant)!")
    with pytest.raises(TemplateSyntaxError, match="enum_value:role"):
        normalize_values(template, {"role": "system"})


def test_canonical_values_are_stable() -> None:
    left = canonical_values_json({"b": 2, "a": "x"})
    right = canonical_values_json({"a": "x", "b": 2})
    assert left == right == b'{"a":"x","b":2}'
