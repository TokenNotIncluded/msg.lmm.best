import base64
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from msgnet.adapters.pancake import Pancake
from msgnet.commerce import Commerce
from msgnet.content import Content
from msgnet.model import Conflict, Denied, Record, encode


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def header(key: rsa.RSAPrivateKey, raw: bytes, timestamp: int = 1000) -> str:
    signature = key.sign(str(timestamp).encode() + b"." + raw, padding.PKCS1v15(), hashes.SHA256())
    return f"t={timestamp},v1={base64.b64encode(signature).decode()}"


def test_webhook_verification_durable_dedup(
    content: Content, signing_key: rsa.RSAPrivateKey
) -> None:
    pem = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    provider = Pancake(pem, "store-1", "prod")
    commerce = Commerce(content.database)
    event: Record = {
        "eventId": "payment-1",
        "eventType": "subscription.payment_succeeded",
        "storeId": "store-1",
        "mode": "prod",
        "data": {"chargedAmount": "1.00"},
    }
    raw = encode(event)
    assert provider.receive(commerce, header(signing_key, raw), raw, now=1000)
    assert not provider.receive(commerce, header(signing_key, raw), raw, now=1000)
    with content.database.transaction(write=False) as tx:
        assert tx.one("SELECT count(*) FROM receipts")[0] == 1
        assert tx.one("SELECT count(*) FROM outbox WHERE done=0")[0] == 1
        assert tx.one("SELECT count(*) FROM transfers")[0] == 0  # No invented fulfillment.
    modified = encode({**event, "data": {"chargedAmount": "9.00"}})
    with pytest.raises(Conflict):
        provider.receive(commerce, header(signing_key, modified), modified, now=1000)
    with pytest.raises(Denied):
        provider.verify(header(signing_key, raw), modified, now=1000)
    with pytest.raises(Denied):
        provider.verify(header(signing_key, raw), raw, now=1400)
    for bad in ({**event, "mode": "test"}, {**event, "storeId": "another-store"}):
        data = encode(bad)
        with pytest.raises(Denied):
            provider.verify(header(signing_key, data), data, now=1000)


def test_cli_help_does_not_import_heavy_modules() -> None:
    script = """
import sys
from msgnet.cli import client, server
for function in (client.main, server.main):
    try:
        function(['--help'])
    except SystemExit as exc:
        assert exc.code == 0
assert 'cryptography' not in sys.modules
assert 'sqlite3' not in sys.modules
assert 'msgnet.content' not in sys.modules
assert 'starlette' not in sys.modules
assert 'uvicorn' not in sys.modules
"""
    subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, timeout=10)


def test_exactly_two_entry_points_and_no_legacy_imports() -> None:
    import tomllib

    root = Path(__file__).parents[1]
    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    assert set(project["project"]["scripts"]) == {"msg", "msgd"}
    assert not (root / "src/msgd").exists()
    assert all(
        "from msgd" not in path.read_text() and "import msgd" not in path.read_text()
        for path in (root / "src").rglob("*.py")
    )


def test_identity_creation_never_overwrites_and_sets_private_mode(tmp_path: Path) -> None:
    from msgnet.cli.client import main

    key = tmp_path / "identity.pem"
    assert main(["init", "--key", str(key)]) == 0
    original = key.read_bytes()
    assert key.stat().st_mode & 0o777 == 0o600
    assert main(["init", "--key", str(key)]) == 2
    assert key.read_bytes() == original
