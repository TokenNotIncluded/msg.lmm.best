import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from msgnet.content import Content
from msgnet.database import Database
from msgnet.model import Conflict, Denied, Invalid
from msgnet.policy import Grant, Principal
from msgnet.templates import Field, Template


def test_history_dedup_archive_and_gc(content: Content, root: Principal) -> None:
    first = content.create(root, "main", b"first\n", {"title": "one"})
    second = content.create(root, "main", b"first\n", {"title": "two"})
    assert content.read(first).oid == content.read(second).oid
    assert content.edit(root, first, 1, b"second\n", {"title": "one"}) == 2
    assert "-first\n+second\n" in content.diff(first, 1, 2)
    content.archive(root, first)
    content.collect()
    assert content.read(first).archived
    assert content.read(first, 1).body == b"first\n"
    assert content.read(first, 2).body == b"second\n"


def test_optimistic_edit_and_archive(content: Content, root: Principal) -> None:
    post = content.create(root, "main", b"one", {"title": "one"})
    content.edit(root, post, 1, b"two", {"title": "two"})
    with pytest.raises(Conflict):
        content.edit(root, post, 1, b"overwrite", {"title": "one"})
    content.archive(root, post)
    with pytest.raises(Denied):
        content.edit(root, post, 2, b"hidden edit", {"title": "one"})


def test_no_implicit_self_or_moderation_permission(content: Content, root: Principal) -> None:
    post = content.create(root, "main", b"one", {"title": "one"})
    with pytest.raises(Denied):
        content.create(Principal("stranger"), "main", b"bad", {"title": "one"})
    editor = Principal("other", (Grant("topic:main", frozenset({"post.edit"})),))
    with pytest.raises(Denied):
        content.edit(editor, post, 1, b"bad", {"title": "one"})


def test_schema_versions_are_pinned(content: Content, root: Principal) -> None:
    post = content.create(root, "main", b"one", {"title": "one"})
    content.topic(root, "main", Template(2, (Field("subject", "string"),)))
    with pytest.raises(Invalid):
        content.edit(root, post, 1, b"bad", {"title": "one"})
    content.edit(root, post, 1, b"two", {"subject": "two"})
    assert content.read(post, 1).schema_version == 1
    assert content.read(post, 2).schema_version == 2
    with pytest.raises(Conflict):
        content.topic(root, "main", Template(2, ()))


def test_partial_write_leaks_only_a_safe_pin(content: Content, root: Principal) -> None:
    good = content.create(root, "main", b"retained", {"title": "one"})
    orphan = ""
    with pytest.raises(RuntimeError), content.database.transaction():
        orphan = content.objects.put(b"uncommitted")
        raise RuntimeError("power loss before SQL commit")
    with content.database.transaction(write=False):
        assert content.objects.get(orphan) == b"uncommitted"
    assert content.collect() == 1
    assert content.read(good).body == b"retained"


def test_process_crash_before_sql_commit(content: Content) -> None:
    script = """
import os, sys
from contextlib import closing
from pathlib import Path
from msgnet.database import Database
from msgnet.objects import Objects
p=Path(sys.argv[1])
with Database(p).transaction() as tx:
    oid=Objects(p/'objects.git').put(b'crash-orphan')
    tx.execute("INSERT INTO accounts(id) VALUES('uncommitted')")
    os._exit(73)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(content.database.root)],
        env=os.environ.copy(),
        check=False,
        timeout=10,
    )
    assert result.returncode == 73
    with content.database.transaction(write=False) as tx:
        assert not tx.all("SELECT id FROM accounts WHERE id='uncommitted'")
    assert content.collect() == 1


def test_legacy_database_is_not_modified(tmp_path: Path) -> None:
    with closing(sqlite3.connect(tmp_path / "msg.db")) as connection, connection:
        connection.execute("CREATE TABLE old_data(secret TEXT)")
        connection.execute("INSERT INTO old_data VALUES('must survive')")
    with pytest.raises(Invalid, match="migration"):
        Database(tmp_path).initialize()
    with closing(sqlite3.connect(tmp_path / "msg.db")) as connection, connection:
        assert connection.execute("SELECT secret FROM old_data").fetchone() == ("must survive",)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)


def test_uninitialized_database_is_not_created(tmp_path: Path) -> None:
    with pytest.raises(sqlite3.OperationalError), Database(tmp_path).transaction():
        pass
    assert not (tmp_path / "msg.db").exists()


def test_object_limit_and_no_revision_side_effect(content: Content, root: Principal) -> None:
    with pytest.raises(Invalid):
        content.create(root, "main", b"x" * 1_048_577, {"title": "one"})
    with content.database.transaction(write=False) as tx:
        assert not tx.all("SELECT id FROM posts")


def test_oid_validation_rejects_git_options_and_paths(content: Content) -> None:
    with pytest.raises(Invalid):
        content.objects.get("--batch")
    with pytest.raises(Invalid):
        content.objects.get("../../passwd")
