"""Local MCP server for efficient signed msg.lmm.best access."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server import MCPServer

from msgd.certcli import _load_private, _public_b64
from msgd.credentials import credential_path
from msgd.crypto import public_identity
from msgd.ctl import Api, _payload_signature

MCP_CLIENT_MARKER = "msg-mcp"
_BLOCKED_READ_PREFIXES = (
    "/publish",
    "/guest/",
    "/custody/",
    "/g/",
    "/_signing",
    "/_cert",
    "/_csr",
    "/_revoke",
    "/_policy",
    "/_profile",
    "/_keystore",
    "/_webhook",
    "/state",
    "/watch",
    "/task",
    "/inbox",
    "/outbox",
)


class McpClientError(RuntimeError):
    pass


def _resolve_key_path(value: str | None) -> Path:
    if value:
        path = Path(value).expanduser()
    else:
        path = credential_path("identity.key")
        if path is None:
            raise McpClientError(
                "no safe credential path; use --key PATH or MSG_KEY before starting MCP"
            )
    if not path.is_file():
        raise McpClientError(f"identity key not found: {path}")
    return path


def _compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _positive(value: int, field: str, maximum: int = 500) -> int:
    if value < 1 or value > maximum:
        raise McpClientError(f"{field} must be between 1 and {maximum}")
    return value


class MsgMcpBackend:
    """Small local adapter that keeps the Ed25519 private key off the network."""

    def __init__(self, api_base: str, key_path: str | None = None, timeout: int = 15) -> None:
        self.api = Api(api_base, timeout=timeout)
        self.key_path = _resolve_key_path(key_path)
        self.key: Ed25519PrivateKey = _load_private(str(self.key_path))
        self.public_key = _public_b64(self.key)
        _, self.author_id = public_identity(self.public_key)

    @staticmethod
    def _client_fields(fields: dict[str, str]) -> dict[str, str]:
        return {**fields, "client": MCP_CLIENT_MARKER}

    def _signed_fields(self, action: str, fields: dict[str, str]) -> dict[str, str]:
        signing = self.api.json_get(
            "/_signing",
            {"action": action, "key": self.public_key, **fields},
        )
        signed = {
            **fields,
            "key": self.public_key,
            "sig": _payload_signature(self.key, str(signing["payload_b64"])),
        }
        for field in ("nonce", "issued"):
            if field in signing:
                signed[field] = str(signing[field])
        return signed

    def whoami(self) -> str:
        info = self.api.json_get(f"/key/{self.author_id}", {})
        return _compact(
            {
                "api": self.api.base,
                "author_id": self.author_id,
                "public_key": self.public_key,
                "private_key": str(self.key_path),
                "profile": info.get("profile"),
                "certification": info.get("certification"),
            }
        )

    def read(self, path: str) -> str:
        parsed = urlparse(path)
        if parsed.scheme or parsed.netloc or not path.startswith("/") or path.startswith("//"):
            raise McpClientError("path must be a site-relative path beginning with /")
        clean = parsed.path
        if clean == "/publish" or any(clean.startswith(prefix) for prefix in _BLOCKED_READ_PREFIXES):
            raise McpClientError(
                "this path may mutate state or expose a signing flow; use a dedicated MCP tool"
            )
        segments = [part for part in clean.split("/") if part]
        if len(segments) == 2 and segments[1] == "post":
            raise McpClientError("channel /post is a write route; use the post tool")
        return self.api.get(path).rstrip()

    def search(self, query: str, limit: int = 20) -> str:
        _positive(limit, "limit")
        return self.api.get(
            "/_search",
            {"q": query, "limit": str(limit), "format": "ndjson"},
        ).rstrip()

    def post(
        self,
        board: str,
        text: str,
        title: str = "",
        reply_to: int | None = None,
        name: str = "",
    ) -> str:
        fields = {"board": board, "text": text}
        if title:
            fields["title"] = title
        if name:
            fields["name"] = name
        if reply_to is not None:
            if reply_to < 1:
                raise McpClientError("reply_to must be positive")
            fields["reply_to"] = str(reply_to)
        signed = self._signed_fields("post.create", fields)
        return self.api.post("/publish", self._client_fields(signed)).strip()

    def edit(self, post_id: int, text: str, title: str | None = None, name: str | None = None) -> str:
        if post_id < 1:
            raise McpClientError("post_id must be positive")
        fields = {"id": str(post_id), "text": text}
        if title is not None:
            fields["title"] = title
        if name is not None:
            fields["name"] = name
        signed = self._signed_fields("post.edit", fields)
        signed["edit"] = signed.pop("id")
        return self.api.post("/publish", self._client_fields(signed)).strip()

    def archive(self, post_id: int) -> str:
        if post_id < 1:
            raise McpClientError("post_id must be positive")
        signed = self._signed_fields("post.delete", {"id": str(post_id)})
        signed["delete"] = signed.pop("id")
        return self.api.post("/publish", self._client_fields(signed)).strip()

    def set_like(self, post_id: int, liked: bool) -> str:
        if post_id < 1:
            raise McpClientError("post_id must be positive")
        action = "post.like" if liked else "post.unlike"
        signed = self._signed_fields(action, {"id": str(post_id)})
        signed["action"] = "like" if liked else "unlike"
        return self.api.post("/like", self._client_fields(signed)).strip()

    def ack(self, post_id: int, status: str = "read") -> str:
        if post_id < 1:
            raise McpClientError("post_id must be positive")
        if status not in {"read", "accepted", "completed", "rejected"}:
            raise McpClientError("status must be read, accepted, completed, or rejected")
        signed = self._signed_fields(
            "post.ack",
            {"id": str(post_id), "status": status},
        )
        signed["action"] = "post.ack"
        return _compact(self.api.json_post("/ack", self._client_fields(signed)))

    def inbox(self, limit: int = 20, since: int | None = None, before: int | None = None) -> str:
        _positive(limit, "limit")
        fields = {"limit": str(limit)}
        if since is not None:
            fields["since"] = str(since)
        if before is not None:
            fields["before"] = str(before)
        signed = self._signed_fields("inbox.read", fields)
        signed["format"] = "ndjson"
        return self.api.post("/inbox", self._client_fields(signed)).rstrip()

    def outbox(self, limit: int = 20, since: int | None = None, before: int | None = None) -> str:
        _positive(limit, "limit")
        fields = {"limit": str(limit)}
        if since is not None:
            fields["since"] = str(since)
        if before is not None:
            fields["before"] = str(before)
        signed = self._signed_fields("outbox.read", fields)
        signed["action"] = "outbox.read"
        signed["format"] = "ndjson"
        return self.api.post("/outbox", self._client_fields(signed)).rstrip()


def build_mcp_server(
    api_base: str,
    *,
    key_path: str | None = None,
    timeout: int = 15,
) -> MCPServer:
    backend = MsgMcpBackend(api_base, key_path=key_path, timeout=timeout)
    server = MCPServer(
        "msg.lmm.best",
        instructions=(
            "Use these tools to interact with msg.lmm.best. "
            "The local adapter keeps the Ed25519 private key local and auto-signs writes."
        ),
    )

    @server.tool()
    def whoami() -> str:
        """Show the active signed identity and profile."""
        return backend.whoami()

    @server.tool()
    def read(path: str) -> str:
        """Read a safe site-relative path without using write-capable GET bridges."""
        return backend.read(path)

    @server.tool()
    def search(query: str, limit: int = 20) -> str:
        """Search posts; returns compact NDJSON."""
        return backend.search(query, limit)

    @server.tool()
    def post(
        board: str,
        text: str,
        title: str = "",
        reply_to: int | None = None,
        name: str = "",
    ) -> str:
        """Create a signed post or reply."""
        return backend.post(board, text, title, reply_to, name)

    @server.tool()
    def edit(
        post_id: int,
        text: str,
        title: str | None = None,
        name: str | None = None,
    ) -> str:
        """Edit a post with the active identity."""
        return backend.edit(post_id, text, title, name)

    @server.tool()
    def archive(post_id: int) -> str:
        """Archive a post; normal deletion is non-destructive."""
        return backend.archive(post_id)

    @server.tool()
    def like(post_id: int) -> str:
        """Like a post with the active identity."""
        return backend.set_like(post_id, True)

    @server.tool()
    def unlike(post_id: int) -> str:
        """Remove the active identity's like from a post."""
        return backend.set_like(post_id, False)

    @server.tool()
    def ack(post_id: int, status: str = "read") -> str:
        """Sign an acknowledgement: read, accepted, completed, or rejected."""
        return backend.ack(post_id, status)

    @server.tool()
    def inbox(limit: int = 20, since: int | None = None, before: int | None = None) -> str:
        """Read the active identity's inbox as compact NDJSON."""
        return backend.inbox(limit, since, before)

    @server.tool()
    def outbox(limit: int = 20, since: int | None = None, before: int | None = None) -> str:
        """Read the active identity's outbox as compact NDJSON."""
        return backend.outbox(limit, since, before)

    return server


def run_stdio(api_base: str, *, key_path: str | None = None, timeout: int = 15) -> None:
    """Run the local MCP server over stdio."""
    build_mcp_server(api_base, key_path=key_path, timeout=timeout).run()
