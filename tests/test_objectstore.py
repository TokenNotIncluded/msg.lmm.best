"""Hybrid SQLite/Git content storage tests."""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from msgd.config import Config
from msgd.objectstore import GitObjectStore
from msgd.store import FileInput, Store


@unittest.skipUnless(shutil.which("git"), "git executable is required")
class GitObjectStoreTests(unittest.TestCase):
    def test_revision_chain_deduplicates_blobs_and_moves_post_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "objects.git"
            objects = GitObjectStore(root)

            first = objects.write_revision(
                7,
                body=b"hello world",
                attachments=(b"same attachment",),
                timestamp=1_700_000_000,
            )
            second = objects.write_revision(
                7,
                body=b"hello world!",
                attachments=(b"same attachment",),
                parent=first.commit_oid,
                timestamp=1_700_000_001,
            )

            self.assertEqual(first.attachment_oids, second.attachment_oids)
            self.assertNotEqual(first.body_oid, second.body_oid)
            self.assertEqual(objects.get_blob(second.body_oid), b"hello world!")

            ref = subprocess.run(
                [
                    shutil.which("git") or "git",
                    "--git-dir",
                    str(root),
                    "rev-parse",
                    "refs/msg/posts/7",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(ref, second.commit_oid)

            commit = subprocess.run(
                [
                    shutil.which("git") or "git",
                    "--git-dir",
                    str(root),
                    "cat-file",
                    "-p",
                    second.commit_oid,
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn(f"parent {first.commit_oid}", commit)


@unittest.skipUnless(shutil.which("git"), "git executable is required")
class HybridStoreTests(unittest.TestCase):
    def test_post_and_attachment_bytes_live_in_git_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "msg.db"
            store = Store(
                Config(
                    database=str(database),
                    object_root=str(root / "objects.git"),
                    object_enabled=True,
                )
            )
            try:
                payload = b"attachment bytes"
                file = FileInput(
                    name="note.txt",
                    content_type="text/plain",
                    data=payload,
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
                post, _ = store.create_post(
                    board="main",
                    body="hello object storage #git",
                    name="tester",
                    title="object backed",
                    files=(file,),
                )

                conn = sqlite3.connect(database)
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT body, body_oid, content_commit FROM posts WHERE id = ?",
                    (post.id,),
                ).fetchone()
                attachment = conn.execute(
                    "SELECT data, object_oid FROM attachments WHERE post_id = ?",
                    (post.id,),
                ).fetchone()
                conn.close()

                assert row is not None
                assert attachment is not None
                self.assertEqual(row["body"], "")
                self.assertTrue(row["body_oid"])
                self.assertTrue(row["content_commit"])
                self.assertEqual(bytes(attachment["data"]), b"")
                self.assertTrue(attachment["object_oid"])

                loaded = store.get_post(post.id)
                assert loaded is not None
                self.assertEqual(loaded.body, "hello object storage #git")
                self.assertEqual(store.attachments(post.id)[0].data, payload)
                self.assertIn("git", store.post_tags(post.id))

                edited = store.edit_post(
                    post=loaded,
                    body="hello object storage after edit #packed",
                )
                self.assertEqual(edited.body, "hello object storage after edit #packed")
                self.assertNotEqual(edited.content_commit, loaded.content_commit)
                self.assertEqual(store.attachments(post.id)[0].data, payload)
                self.assertIn("packed", store.post_tags(post.id))

                found, _ = store.search_posts(
                    __import__("msgd.search", fromlist=["parse_search_query"]).parse_search_query(
                        "after edit"
                    ),
                    limit=20,
                )
                self.assertEqual([item.id for item in found], [post.id])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
