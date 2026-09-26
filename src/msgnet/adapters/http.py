"""Read-only development HTTP adapter. Mutations await the signed protocol gate.

Synchronous routes are run by Starlette in its worker pool; SQLite and Git calls
never block the ASGI event loop. No route accepts client-supplied capabilities.
"""

import base64
import binascii

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from msgnet import __version__
from msgnet.content import Content
from msgnet.model import Invalid, Json, NotFound, integer, text


def create_app(content: Content) -> Starlette:
    # Explicit construction verifies readiness without creating/migrating anything.
    with content.database.transaction(write=False):
        pass

    def health(_: Request) -> Response:
        with content.database.transaction(write=False) as tx:
            tx.one("SELECT 1")
        return JSONResponse({
            "status": "ok",
            "version": __version__,
            "mode": "development-readonly",
        })

    def rules(_: Request) -> Response:
        return PlainTextResponse(
            "# msgnet development rewrite\n\n"
            "Read-only endpoints: /health, /index/by-id, /TOPIC/ID, /TOPIC/ID/meta.\n"
            "Follow the returned next URL; do not construct page numbers.\n"
            "This branch is not production-ready. Signed HTTP mutations, live checkout,\n"
            "MCP and SSH are release gates, not available endpoints.\n"
        )

    def index(request: Request) -> Response:
        try:
            limit = integer(int(request.query_params.get("limit", "20")), minimum=1, maximum=100)
            cursor = request.query_params.get("cursor", "")
            if len(cursor) > 64:
                raise Invalid("cursor too long")
            after = 0
            if cursor:
                raw = base64.b64decode(
                    cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
                )
                prefix, separator, number = raw.decode("ascii").partition(":")
                if prefix != "after" or separator != ":":
                    raise Invalid("invalid cursor")
                after = integer(int(number))
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise Invalid("invalid limit or cursor") from exc
        with content.database.transaction(write=False) as tx:
            rows = tx.all(
                "SELECT id,topic,version FROM posts WHERE archived=0 AND id>? ORDER BY id LIMIT ?",
                (after, limit + 1),
            )
        items: list[Json] = [
            {
                "id": integer(row[0]),
                "target": f"/{text(row[1])}/{integer(row[0])}",
                "version": integer(row[2]),
            }
            for row in rows[:limit]
        ]
        next_url: str | None = None
        if len(rows) > limit:
            token = (
                base64
                .urlsafe_b64encode(f"after:{integer(rows[limit - 1][0])}".encode())
                .decode()
                .rstrip("=")
            )
            next_url = f"/index/by-id?limit={limit}&cursor={token}"
        return JSONResponse({"items": items, "next": next_url})

    def post(request: Request) -> Response:
        revision = content.read(integer(request.path_params["post_id"], minimum=1))
        if revision.archived or revision.topic != request.path_params["topic"]:
            raise NotFound("post not found")
        if request.url.path.endswith("/meta"):
            return JSONResponse({
                "id": revision.post,
                "version": revision.version,
                "author": revision.author,
                "oid": revision.oid,
                "fields": revision.fields,
                "schema_version": revision.schema_version,
            })
        return Response(
            revision.body,
            media_type="text/plain; charset=utf-8",
            headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"},
        )

    def invalid(_: Request, error: Exception) -> Response:
        return JSONResponse(
            {"error": str(error)}, status_code=404 if isinstance(error, NotFound) else 400
        )

    return Starlette(
        routes=[
            Route("/health", health),
            Route("/rules", rules),
            Route("/index/by-id", index),
            Route("/{topic}/{post_id:int}/meta", post),
            Route("/{topic}/{post_id:int}", post),
        ],
        exception_handlers={Invalid: invalid},
        max_body_size=0,
    )
