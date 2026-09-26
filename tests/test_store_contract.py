"""The catalog belongs to published posts, never packages or deployment settings."""

from pathlib import Path

import pytest

from msgnet.commerce import Commerce
from msgnet.config import Config
from msgnet.content import Content
from msgnet.model import Denied, Invalid, NotFound, Record, decode
from msgnet.policy import Principal
from msgnet.templates import Field, Template

ROOT = Path(__file__).resolve().parents[1]


def store_template() -> Template:
    return Template.parse(decode((ROOT / "config/templates/store.json").read_bytes()))


def product_fields(title: str = "Independent offer", price: int = 347) -> Record:
    return {"title": title, "price_cents": price, "currency": "USD", "enabled": True}


def test_installation_has_no_bundled_products(content: Content) -> None:
    content.initialize()
    with content.database.transaction(write=False) as tx:
        assert tx.one("SELECT count(*) FROM posts WHERE topic='store'")[0] == 0
    assert not (ROOT / "config/products").exists()


def test_starter_schema_has_only_common_product_fields() -> None:
    template = store_template()
    assert {field.name for field in template.fields} == {
        "title",
        "price_cents",
        "currency",
        "enabled",
    }
    template.validate(product_fields())


@pytest.mark.parametrize(("title", "price"), [("Offer A", 347), ("Bundle B", 6203), ("服务 C", 1)])
def test_any_published_product_uses_its_own_price(
    content: Content, root: Principal, title: str, price: int
) -> None:
    content.topic(root, "store", store_template())
    fields = product_fields(title, price)
    product = content.create(root, "store", b"operator-published offer", fields)
    order = Commerce(content.database).checkout(Principal("buyer"), product, "buy", now=1)
    assert order.product == product
    assert order.snapshot == {"fields": fields, "seller": root.subject}


def test_operator_schema_extensions_are_data_not_implicit_entitlements(
    content: Content, root: Principal
) -> None:
    base = store_template()
    content.topic(root, "store", base)
    content.topic(
        root,
        "store",
        Template(
            base.version + 1,
            (
                *base.fields,
                Field("period_days", "integer", False, 1000),
                Field("capacity_bytes", "integer", False, 10**9),
            ),
        ),
    )
    fields: Record = {**product_fields(), "period_days": 45, "capacity_bytes": 37_000_000}
    product = content.create(root, "store", b"custom data; no fulfillment claim", fields)
    order = Commerce(content.database).checkout(Principal("buyer"), product, "buy", now=1)
    assert order.snapshot["fields"] == fields
    # Optional custom fields must not turn the store into one particular product category.
    content.create(root, "store", b"another category", product_fields("Unrelated offer"))


def test_initialization_does_not_reset_or_republish_products(
    content: Content, root: Principal
) -> None:
    content.topic(root, "store", store_template())
    fields = product_fields()
    product = content.create(root, "store", b"original offer", fields)
    updated: Record = {**fields, "price_cents": 819, "enabled": False}
    content.edit(root, product, 1, b"operator changed offer", updated)
    content.initialize()
    revision = content.read(product)
    assert revision.version == 2 and revision.fields == updated
    with content.database.transaction(write=False) as tx:
        assert tx.one("SELECT count(*) FROM posts WHERE topic='store'")[0] == 1


@pytest.mark.parametrize("state", ["disabled", "archived", "outside-store"])
def test_unavailable_and_non_store_posts_cannot_be_bought(
    content: Content, root: Principal, state: str
) -> None:
    topic = "elsewhere" if state == "outside-store" else "store"
    content.topic(root, topic, store_template())
    fields = product_fields()
    if state == "disabled":
        fields["enabled"] = False
    product = content.create(root, topic, b"not for sale", fields)
    if state == "archived":
        content.archive(root, product)
    error = Invalid if state == "disabled" else NotFound
    with pytest.raises(error):
        Commerce(content.database).checkout(Principal("buyer"), product, "buy", now=1)
    with content.database.transaction(write=False) as tx:
        assert tx.one("SELECT count(*) FROM orders")[0] == 0


def test_product_publication_requires_existing_authority(content: Content, root: Principal) -> None:
    content.topic(root, "store", store_template())
    with pytest.raises(Denied):
        content.create(Principal("seller-without-grant"), "store", b"offer", product_fields())


def test_infrastructure_configuration_is_not_a_catalog(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(f'data = "{tmp_path.as_posix()}"\nproducts = []\n')
    with pytest.raises(Invalid, match="unknown configuration key"):
        Config.load(config)
