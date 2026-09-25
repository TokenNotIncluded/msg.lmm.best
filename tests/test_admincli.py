"""End-to-end tests for msgd-admin."""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from msgd.admincli import (
    AdminError,
    Api,
    _parse_home_policies,
    approve,
    delete_post,
    reject,
    resolve_csr,
    revoke,
    set_policy,
)
from msgd.config import Config
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign_payload(key: Ed25519PrivateKey, payload_b64: str) -> str:
    return base64.b64encode(
        key.sign(base64.b64decode(payload_b64))
    ).decode("ascii")


class AdminCliCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root_key = Ed25519PrivateKey.generate()
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(self.root_key) + "\n")

        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            root_public_key=str(root_public),
            max_storage_bytes=500_000,
            max_post_bytes=16_384,
            max_post_bytes_post=65_536,
            write_burst=200,
            write_per_minute=2000,
            read_per_minute=2000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.api = Api(f"http://{host}:{port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def create_csr(
        self,
        applicant: Ed25519PrivateKey,
        *,
        topic: str = "main",
        actions: tuple[str, ...] = ("post.create",),
        message: str = "admin-cli test",
    ) -> dict:
        grants = [
            {
                "topic": topic,
                "actions": list(actions),
            }
        ]
        grants_json = json.dumps(grants, separators=(",", ":"))
        signing = self.api.json_get(
            "/_signing",
            {
                "action": "cert.request",
                "key": public_b64(applicant),
                "grants": grants_json,
                "message": message,
            },
        )
        return self.api.json_post(
            "/_csr",
            {
                "key": public_b64(applicant),
                "sig": sign_payload(applicant, signing["payload_b64"]),
                "nonce": signing["nonce"],
                "issued": str(signing["issued"]),
                "grants": grants_json,
                "message": message,
            },
        )

    def latest_request_audit_post(self):
        posts = self.server.board.store.list_posts(
            board="ca",
            limit=50,
            order="desc",
        )
        return next(post for post in posts if post.title.startswith("[REQUEST] CSR #"))

    def test_approve_accepts_ca_audit_post_id(self) -> None:
        applicant = Ed25519PrivateKey.generate()
        csr = self.create_csr(applicant)
        audit = self.latest_request_audit_post()

        self.assertEqual(resolve_csr(self.api, str(audit.id)), csr["id"])
        self.assertEqual(resolve_csr(self.api, f"/ca/{audit.id}"), csr["id"])
        self.assertEqual(resolve_csr(self.api, f"csr:{csr['id']}"), csr["id"])

        result = approve(
            self.api,
            self.root_key,
            str(audit.id),
            days=30,
        )
        self.assertEqual(result["csr"], csr["id"])
        self.assertEqual(result["subject_id"], csr["subject_id"])

        updated = self.api.json_get("/_csr", {"id": str(csr["id"])})
        self.assertEqual(updated["status"], "issued")
        self.assertEqual(updated["certificate_serial"], result["serial"])

    def test_approve_can_narrow_requested_grants(self) -> None:
        applicant = Ed25519PrivateKey.generate()
        csr = self.create_csr(
            applicant,
            actions=("post.create", "post.edit.self", "post.delete.self"),
        )

        result = approve(
            self.api,
            self.root_key,
            f"csr:{csr['id']}",
            grants=[
                {
                    "topic": "main",
                    "actions": ["post.create"],
                }
            ],
        )
        cert = self.api.json_get("/_cert", {"serial": result["serial"]})
        body = json.loads(cert["body"])
        self.assertEqual(
            body["grants"],
            [{"topic": "main", "actions": ["post.create"]}],
        )

    def test_reject_revoke_policy_and_delete(self) -> None:
        applicant = Ed25519PrivateKey.generate()
        csr = self.create_csr(applicant, topic="skills")
        rejected = reject(
            self.api,
            self.root_key,
            str(csr["id"]),
            reason="not approved",
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["reason"], "not approved")

        member = Ed25519PrivateKey.generate()
        csr2 = self.create_csr(member)
        issued = approve(self.api, self.root_key, str(csr2["id"]))
        serial = issued["serial"]

        response = revoke(
            self.api,
            self.root_key,
            serial,
            reason="key compromised",
        )
        self.assertIn("action=revoke", response)
        revocations = self.api.json_get("/_revocations")
        row = next(item for item in revocations if item["serial"] == serial)
        self.assertEqual(row["reason"], "key compromised")

        policy = set_policy(self.api, self.root_key, "main", 1)
        self.assertEqual(policy["permissions"], 1)

        text = "temporary admin deletion test"
        signing = self.api.json_get(
            "/_signing",
            {
                "action": "post.create",
                "key": public_b64(self.root_key),
                "board": "main",
                "text": text,
            },
        )
        created = self.api.post(
            "/publish",
            {
                "board": "main",
                "text": text,
                "key": public_b64(self.root_key),
                "sig": sign_payload(self.root_key, signing["payload_b64"]),
                "nonce": signing["nonce"],
                "issued": str(signing["issued"]),
            },
        )
        post_id = int(
            dict(
                line.split("=", 1)
                for line in created.splitlines()
                if "=" in line
            )["id"]
        )
        deleted = delete_post(self.api, self.root_key, post_id)
        self.assertIn("action=delete", deleted)
        self.assertIsNone(self.server.board.store.get_post(post_id))

    def test_ca_system_post_cannot_be_deleted_even_by_root_cli(self) -> None:
        self.create_csr(Ed25519PrivateKey.generate())
        audit = self.latest_request_audit_post()
        with self.assertRaises(AdminError):
            delete_post(self.api, self.root_key, audit.id)

    def test_policy_table_parser(self) -> None:
        rows = _parse_home_policies(self.api.get("/"))
        policies = {topic: perm for topic, _, perm, _ in rows}
        self.assertEqual(policies["ca"], 0)
        self.assertEqual(policies["main"], 7)


if __name__ == "__main__":
    unittest.main()
