from pathlib import Path

import pytest

from msgnet.content import Content
from msgnet.database import Database
from msgnet.objects import Objects
from msgnet.policy import Grant, Principal
from msgnet.templates import Field, Template


@pytest.fixture
def root() -> Principal:
    return Principal(
        "root",
        (
            Grant(
                "*",
                frozenset({
                    "topic.configure",
                    "post.create",
                    "post.edit",
                    "post.archive",
                    "post.moderate",
                }),
            ),
        ),
    )


@pytest.fixture
def content(tmp_path: Path, root: Principal) -> Content:
    service = Content(Database(tmp_path), Objects(tmp_path / "objects.git"))
    service.initialize()
    service.topic(root, "main", Template(1, (Field("title", "string", maximum=64),)))
    return service
