from starlette.testclient import TestClient

from msgnet.adapters.http import create_app
from msgnet.content import Content
from msgnet.policy import Principal


def test_read_only_routes_and_metadata(content: Content, root: Principal) -> None:
    post = content.create(root, "main", b"<script>not executable</script>", {"title": "one"})
    with TestClient(create_app(content)) as client:
        assert client.get("/health").json()["mode"] == "development-readonly"
        response = client.get(f"/main/{post}")
        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "text/plain" in response.headers["content-type"]
        assert client.get(f"/main/{post}/meta").json()["version"] == 1
        assert client.get(f"/wrong-topic/{post}").status_code == 404
        assert client.post(f"/main/{post}").status_code == 405
        content.archive(root, post)
        assert client.get(f"/main/{post}").status_code == 404
        assert client.get(f"/main/{post}/meta").status_code == 404


def test_cursor_pagination_and_malformed_input(content: Content, root: Principal) -> None:
    posts = [content.create(root, "main", b"x", {"title": "one"}) for _ in range(5)]
    with TestClient(create_app(content)) as client:
        first = client.get("/index/by-id?limit=2").json()
        assert [item["id"] for item in first["items"]] == posts[:2]
        second = client.get(first["next"]).json()
        third = client.get(second["next"]).json()
        assert [item["id"] for item in third["items"]] == posts[4:]
        assert third["next"] is None
        for query in ("limit=0", "limit=101", "limit=a", "cursor=broken!", "cursor=" + "a" * 65):
            assert client.get("/index/by-id?" + query).status_code == 400
