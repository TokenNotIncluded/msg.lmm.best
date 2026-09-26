"""SQLite owns transactions; a filesystem lock coordinates SQL and Git maintenance."""

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
lazy import fcntl

from msgnet.model import Invalid, NotFound

type Parameter = int | str | bytes | None
SCHEMA = """
CREATE TABLE topics(name TEXT PRIMARY KEY, template TEXT NOT NULL) STRICT;
CREATE TABLE posts(id INTEGER PRIMARY KEY, topic TEXT NOT NULL REFERENCES topics(name),
 author TEXT NOT NULL, version INTEGER NOT NULL, archived INTEGER NOT NULL DEFAULT 0
 CHECK(archived IN (0,1))) STRICT;
CREATE TABLE revisions(post INTEGER NOT NULL REFERENCES posts(id), version INTEGER NOT NULL,
 oid TEXT NOT NULL, fields TEXT NOT NULL, schema_version INTEGER NOT NULL,
 PRIMARY KEY(post,version)) STRICT;
CREATE TABLE accounts(id TEXT PRIMARY KEY, balance INTEGER NOT NULL DEFAULT 0,
 CHECK(balance>=0 OR id='system.clearing')) STRICT;
CREATE TABLE transfers(id TEXT PRIMARY KEY, debit TEXT NOT NULL REFERENCES accounts(id),
 credit TEXT NOT NULL REFERENCES accounts(id), amount INTEGER NOT NULL CHECK(amount>0)) STRICT;
CREATE TRIGGER transfers_immutable_update BEFORE UPDATE ON transfers
 BEGIN SELECT RAISE(ABORT,'immutable ledger'); END;
CREATE TRIGGER transfers_immutable_delete BEFORE DELETE ON transfers
 BEGIN SELECT RAISE(ABORT,'immutable ledger'); END;
CREATE TABLE orders(id TEXT PRIMARY KEY, buyer TEXT NOT NULL, product INTEGER NOT NULL,
 revision INTEGER NOT NULL, snapshot TEXT NOT NULL, expires INTEGER NOT NULL,
 request_key TEXT NOT NULL, UNIQUE(buyer,request_key)) STRICT;
CREATE TABLE receipts(id TEXT PRIMARY KEY, digest TEXT NOT NULL, body BLOB NOT NULL,
 received INTEGER NOT NULL) STRICT;
CREATE TABLE outbox(id TEXT PRIMARY KEY REFERENCES receipts(id), attempts INTEGER NOT NULL DEFAULT 0,
 available INTEGER NOT NULL, done INTEGER NOT NULL DEFAULT 0 CHECK(done IN(0,1))) STRICT;
"""
APPLICATION_ID = 0x4D534731


@dataclass(frozen=True, slots=True)
class Transaction:
    connection: sqlite3.Connection

    def execute(self, sql: str, parameters: Sequence[Parameter] = ()) -> int:
        cursor = self.connection.execute(sql, parameters)
        return cursor.lastrowid or 0

    def one(self, sql: str, parameters: Sequence[Parameter] = ()) -> tuple[object, ...]:
        row: object = self.connection.execute(sql, parameters).fetchone()
        if not isinstance(row, tuple):
            raise NotFound("resource not found")
        return row

    def all(self, sql: str, parameters: Sequence[Parameter] = ()) -> list[tuple[object, ...]]:
        return list(self.connection.execute(sql, parameters).fetchall())


@dataclass(frozen=True, slots=True)
class Database:
    root: Path

    @contextmanager
    def lock(self, *, write: bool) -> Iterator[None]:
        with (self.root / ".storage.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def initialize(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.lock(write=True):
            connection = sqlite3.connect(self.root / "msg.db", autocommit=True)
            try:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                app_id = connection.execute("PRAGMA application_id").fetchone()[0]
                tables = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
                if tables or version or app_id:
                    if version != 1 or app_id != APPLICATION_ID:
                        raise Invalid("unrecognized database; explicit migration required")
                    return
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.executescript(
                    "BEGIN IMMEDIATE;"
                    + SCHEMA
                    + f"PRAGMA application_id={APPLICATION_ID};"
                    + "PRAGMA user_version=1; COMMIT;"
                )
            finally:
                connection.close()

    @contextmanager
    def transaction(self, *, write: bool = True) -> Iterator[Transaction]:
        with self.lock(write=write):
            uri = (self.root / "msg.db").resolve().as_uri() + "?mode=rw"
            connection = sqlite3.connect(uri, uri=True, autocommit=True, timeout=10)
            try:
                if (
                    connection.execute("PRAGMA user_version").fetchone()[0] != 1
                    or connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                ):
                    raise Invalid("unrecognized database; explicit migration required")
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA synchronous=FULL")
                if not write:
                    connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield Transaction(connection)
                connection.execute("COMMIT")
            finally:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
