"""Versioned content use cases shared by all future transports."""

import difflib
from dataclasses import dataclass

from msgnet.database import Database
from msgnet.model import (
    Conflict,
    Denied,
    Invalid,
    Record,
    decode,
    encode,
    identifier,
    integer,
    text,
)
from msgnet.objects import Objects
from msgnet.policy import Principal
from msgnet.templates import Template


@dataclass(frozen=True, slots=True)
class Revision:
    post: int
    version: int
    topic: str
    author: str
    oid: str
    body: bytes
    fields: Record
    schema_version: int
    archived: bool


@dataclass(frozen=True, slots=True)
class Content:
    database: Database
    objects: Objects

    def initialize(self) -> None:
        self.database.initialize()
        with self.database.lock(write=True):
            self.objects.initialize()

    def topic(self, actor: Principal, name: str, template: Template) -> None:
        name = identifier(name)
        actor.require(f"topic:{name}", "topic.configure")
        with self.database.transaction() as tx:
            existing = tx.all("SELECT template FROM topics WHERE name=?", (name,))
            if existing:
                previous = Template.parse(decode(text(existing[0][0], maximum=65536).encode()))
                if template.version <= previous.version:
                    raise Conflict("template version must increase")
            tx.execute(
                "INSERT INTO topics VALUES(?,?) ON CONFLICT(name) DO UPDATE SET template=excluded.template",
                (name, encode(template.record()).decode()),
            )

    def create(self, actor: Principal, topic: str, body: bytes, fields: Record) -> int:
        topic = identifier(topic)
        actor.require(f"topic:{topic}", "post.create")
        with self.database.transaction() as tx:
            raw = text(
                tx.one("SELECT template FROM topics WHERE name=?", (topic,))[0], maximum=65536
            )
            template = Template.parse(decode(raw.encode()))
            template.validate(fields)
            encoded = encode(fields).decode()
            oid = self.objects.put(body)
            post = tx.execute(
                "INSERT INTO posts(topic,author,version) VALUES(?,?,1)", (topic, actor.subject)
            )
            tx.execute(
                "INSERT INTO revisions VALUES(?,?,?,?,?)", (post, 1, oid, encoded, template.version)
            )
            return post

    def edit(self, actor: Principal, post: int, expected: int, body: bytes, fields: Record) -> int:
        integer(post, minimum=1)
        integer(expected, minimum=1)
        with self.database.transaction() as tx:
            topic, author, version, archived = tx.one(
                "SELECT topic,author,version,archived FROM posts WHERE id=?", (post,)
            )
            actor.require(f"topic:{text(topic)}", "post.edit")
            if actor.subject != author:
                actor.require(f"topic:{text(topic)}", "post.moderate")
            if archived:
                raise Denied("archived posts cannot be edited")
            if version != expected:
                raise Conflict("post revision changed")
            raw = text(
                tx.one("SELECT template FROM topics WHERE name=?", (text(topic),))[0], maximum=65536
            )
            template = Template.parse(decode(raw.encode()))
            template.validate(fields)
            oid = self.objects.put(body)
            version = expected + 1
            tx.execute(
                "INSERT INTO revisions VALUES(?,?,?,?,?)",
                (post, version, oid, encode(fields).decode(), template.version),
            )
            tx.execute("UPDATE posts SET version=? WHERE id=?", (version, post))
            return version

    def read(self, post: int, version: int | None = None) -> Revision:
        integer(post, minimum=1)
        if version is not None:
            integer(version, minimum=1)
        with self.database.transaction(write=False) as tx:
            row = tx.one(
                "SELECT p.topic,p.author,p.archived,r.version,r.oid,r.fields,r.schema_version "
                "FROM posts p JOIN revisions r ON r.post=p.id "
                "WHERE p.id=? AND r.version=coalesce(?,p.version)",
                (post, version),
            )
            oid = text(row[4])
            return Revision(
                post,
                integer(row[3]),
                text(row[0]),
                text(row[1]),
                oid,
                self.objects.get(oid),
                decode(text(row[5], maximum=1_048_576).encode()),
                integer(row[6]),
                bool(row[2]),
            )

    def archive(self, actor: Principal, post: int) -> None:
        integer(post, minimum=1)
        with self.database.transaction() as tx:
            topic, author = tx.one("SELECT topic,author FROM posts WHERE id=?", (post,))
            actor.require(f"topic:{text(topic)}", "post.archive")
            if actor.subject != author:
                actor.require(f"topic:{text(topic)}", "post.moderate")
            tx.execute("UPDATE posts SET archived=1 WHERE id=?", (post,))

    def diff(self, post: int, before: int, after: int) -> str:
        left, right = self.read(post, before), self.read(post, after)
        try:
            a, b = (
                left.body.decode().splitlines(keepends=True),
                right.body.decode().splitlines(keepends=True),
            )
        except UnicodeDecodeError as exc:
            raise Invalid("text diff requires UTF-8 content") from exc
        return "".join(
            difflib.unified_diff(
                a, b, fromfile=f"post:{post}@{before}", tofile=f"post:{post}@{after}"
            )
        )

    def collect(self) -> int:
        with self.database.transaction() as tx:
            live = frozenset(text(row[0]) for row in tx.all("SELECT DISTINCT oid FROM revisions"))
            return self.objects.collect(live)
