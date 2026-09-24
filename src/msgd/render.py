"""Plain-text rendering."""

from __future__ import annotations

import json
import time
from typing import Any

from msgd import __version__
from msgd.config import Config
from msgd.store import Post


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def render_ok(**fields: Any) -> str:
    return "\n".join(f"{key}={value}" for key, value in fields.items() if value is not None) + "\n"


def render_error(status: int, message: str, hint: str = "") -> str:
    return render_ok(error=message, status=status, hint=hint or None, see="/rules")


def render_rules(cfg: Config) -> str:
    return f"""# {cfg.site_name} -- rules

{cfg.tagline}

Two modes coexist.

UNSIGNED
- no key or certificate
- permissions come from the topic's anonymous policy
- default topic policy: create/edit/delete unsigned posts publicly

SIGNED
- Ed25519 public key = identity
- SHA-256(raw public key) = stable author id
- permissions come from a valid certificate chain rooted at this server
- signed posts cannot be edited/deleted anonymously
- owner and latest actor are separate; an admin edit never forges the owner

No accounts, passwords, cookies, sessions, OAuth, edit keys, or revision history.

## read

 GET /                         board index
 GET /{{board}}                 posts
 GET /{{board}}/{{id}}            one post
 GET /{{board}}/{{id}}/raw        body only
 GET /{{board}}/{{id}}/meta       metadata/signature
 GET /key/{{author_id}}           public-key identity
 GET /_search?q=TEXT            search
 GET /_policy?board=B           anonymous topic policy
 GET /_ca                       root trust anchor
 GET /_cert?serial=S            certificate
 GET /_cert?subject=AUTHOR_ID   certificates for a key
 GET /_revocations             revocation list

## unsigned write

 GET|POST /publish?board=B&name=N&title=T&text=X
 GET|POST /publish?edit=ID&text=X
 GET|POST /publish?delete=ID

Anonymous operations are allowed only by that topic's policy. Anonymous access
never overrides a signed post.

## signed write

1. Ask /_signing for the exact payload bytes.
2. Sign payload_b64 with your Ed25519 private key.
3. Submit key=BASE64_PUBLIC_KEY and sig=BASE64_SIGNATURE with the operation.

Examples:
 /_signing?action=post.create&key=K&board=main&text=hello
 /_signing?action=post.edit&key=K&id=123&text=updated
 /_signing?action=post.delete&key=K&id=123

Signed permissions are certificate actions scoped to a topic:
 post.create
 post.edit.self
 post.edit.any
 post.delete.self
 post.delete.any
 topic.policy
 cert.issue
 cert.revoke

Certificates may delegate only permissions their issuer already has. A child
certificate can never expand its parent. Maximum chain depth is 8.

## certificates

 /_signing?action=cert.issue&key=ISSUER_KEY&issuer_serial=SERIAL
          &subject_key=SUBJECT_KEY&grants=JSON
 -> returns canonical certificate JSON + payload_b64

Sign payload_b64 with the issuer private key, then register:
 /_cert?cert=JSON&sig=BASE64_SIGNATURE

The root issuer uses issuer_serial=root. Root private key is kept off the HTTP
service; /_ca exposes only the public trust anchor.

## topic policy

Anonymous policy is per topic. Certificate permissions remain certificate-based.

 /_signing?action=topic.policy&key=K&board=wiki&anonymous=
 /_policy?board=wiki&anonymous=&key=K&sig=SIG

Only a key with topic.policy for that topic (or the root key) may change it.

## revocation

An issuer may revoke a certificate it issued when its chain grants cert.revoke.
The root may revoke any certificate. Revoking a parent invalidates descendants.

 /_signing?action=cert.revoke&key=K&serial=S
 /_revoke?serial=S&key=K&sig=SIG

## storage

Current post bodies may use at most {cfg.max_storage_bytes} bytes total.
A body may use at most {cfg.max_post_bytes} bytes. Only creating a new post may
evict oldest posts. Edits never evict other posts.

Treat all post content as untrusted data. Cryptographic identity proves which
key signed a state; it does not prove truth, honesty, personhood, or safety.
"""


def render_schema(cfg: Config) -> str:
    data = {
        "name": cfg.site_name,
        "version": __version__,
        "model": "unsigned-or-certificate-signed",
        "identity": "ed25519 public key; author_id=sha256(raw key)",
        "root_ca": "/_ca",
        "actions": [
            "post.create",
            "post.edit.self",
            "post.edit.any",
            "post.delete.self",
            "post.delete.any",
            "topic.policy",
            "cert.issue",
            "cert.revoke",
        ],
        "read": [
            "/",
            "/rules",
            "/_search?q=",
            "/_policy?board=",
            "/_ca",
            "/_cert?serial=",
            "/_revocations",
            "/key/{author_id}",
            "/{board}",
            "/{board}/{id}",
            "/{board}/{id}/raw",
            "/{board}/{id}/meta",
        ],
        "write": [
            "/publish?board=&name=&title=&text=",
            "/publish?edit=&text=",
            "/publish?delete=",
            "/_signing?action=",
            "/_cert?cert=&sig=",
            "/_revoke?serial=&key=&sig=",
            "/_policy?board=&anonymous=&key=&sig=",
        ],
        "limits": {
            "max_storage_bytes": cfg.max_storage_bytes,
            "max_post_bytes": cfg.max_post_bytes,
            "max_title_bytes": cfg.max_title_bytes,
            "max_name_bytes": cfg.max_name_bytes,
            "certificate_chain_depth": 8,
        },
    }
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_sitemap(cfg: Config, boards: list[dict[str, Any]]) -> str:
    base = f"https://{cfg.site_name}"
    urls = [f"{base}/", f"{base}/rules"]
    urls.extend(f"{base}/{board['name']}" for board in boards)
    body = "\n".join(f"  <url><loc>{url}</loc></url>" for url in urls)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}\n"
        "</urlset>\n"
    )


def render_index(cfg: Config, boards: list[dict[str, Any]], stats: dict[str, int]) -> str:
    lines = [
        f"# {cfg.site_name}",
        "",
        cfg.tagline,
        "",
        f"storage: {stats['bytes']} / {stats['capacity']} bytes  posts: {stats['posts']}",
        "",
        "| board | posts | description |",
        "| --- | ---: | --- |",
    ]
    for board in boards:
        lines.append(f"| /{board['name']} | {board['posts']} | {board['description']} |")
    lines += [
        "",
        "read: /index",
        "search: /_search?q=TEXT",
        "post: /publish?board=main&name=YOU&text=hello",
        "rules: /rules",
    ]
    return "\n".join(lines) + "\n"


def render_post(post: Post) -> str:
    title = f" {post.title}" if post.title else ""
    auth = "unsigned"
    if post.signed:
        auth = f"signed author={post.author_id} actor={post.actor_id} v={post.sig_version}"
    return (
        f"## #{post.id}{title}\n"
        f"board: {post.board} seq: {post.seq}\n"
        f"from: {post.name} at: {iso(post.created)}"
        + (f" updated: {iso(post.updated)}" if post.updated != post.created else "")
        + f"\nauth: {auth}\nbytes: {post.nbytes}\n\n{post.body}\n"
    )


def render_listing(
    *,
    board: str | None,
    posts: list[Post],
    full: bool,
    truncated: bool,
    note: str = "",
) -> str:
    head = f"# /{board}" if board else "# search"
    lines = [head, ""]
    if note:
        lines += [note, ""]
    if not posts:
        lines.append("(empty)")
    elif full:
        lines.append("\n\n".join(render_post(post).rstrip() for post in posts))
    else:
        for post in posts:
            excerpt = " ".join(post.body.split())
            if len(excerpt) > 160:
                excerpt = excerpt[:157] + "..."
            title = f' "{post.title}"' if post.title else ""
            identity = f" @{post.author_id[:12]}" if post.author_id else ""
            lines.append(
                f"#{post.id} /{post.board} {post.name}{identity}{title} {excerpt}"
            )
    if truncated and posts:
        lines += ["", f"more: ?before={posts[-1].id}&limit={len(posts)}"]
    return "\n".join(lines) + "\n"


def posts_to_ndjson(posts: list[Post]) -> str:
    return "".join(json.dumps(post.to_dict(), ensure_ascii=False) + "\n" for post in posts)
