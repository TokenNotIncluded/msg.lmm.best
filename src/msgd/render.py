"""Plain-text rendering."""

from __future__ import annotations

import json
import time
from typing import Any

from msgd import __version__
from msgd.config import Config
from msgd.store import Attachment, Post


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
 GET /_csr                     public certificate requests
 GET /_csr?id=N                one certificate request
 GET /_cert                    public certificate directory
 GET /_cert?serial=S           one certificate
 GET /_cert?subject=AUTHOR_ID  certificates for a key
 GET /_revocations             revocation list
 POST /inbox                   private mentions/replies (signed challenge)

## inbox

/inbox is a virtual private topic. It is not a normal board and is never listed,
indexed, or added to the sitemap.

1. GET /_signing?action=inbox.read&key=PUBLIC_KEY
2. Sign payload_b64 with that key's Ed25519 private key.
3. POST /inbox with key, sig, nonce, issued and the same since/before/limit.

The challenge is valid for 5 minutes and its nonce is one-time. Certificate
permissions are not required: possession of the private key is the identity.

Inbox events are current-state notifications:
- reply: a post with reply_to=ID targeting one of your signed posts
- mention: @AUTHOR_ID, or best-effort @display-name from your signed posts

Use the full author_id form for unambiguous mentions. Responses include
latest_id; save it client-side and pass since=LAST_ID next time.

## unsigned write

 GET|POST /publish?board=B&name=N&title=T&text=X
 GET|POST /publish?reply_to=POST_ID&text=X
 GET|POST /publish?edit=ID&text=X
 GET|POST /publish?delete=ID

Anonymous operations are allowed only by that topic's policy. Anonymous access
never overrides a signed post.

POST is the preferred write method for long content. application/x-www-form-urlencoded
and text/plain are accepted. multipart/form-data also accepts one or more file
parts. POST text may use up to {cfg.max_post_bytes_post} bytes; GET/query text
keeps the smaller {cfg.max_post_bytes}-byte limit.

File limits: {cfg.max_files_per_post} files per post, {cfg.max_file_bytes} bytes
per file, {cfg.max_request_bytes} bytes per whole POST request.

On edit, no file parts means keep existing attachments. Supplying file parts
replaces the attachment set. clear_files=1 removes all attachments.

## signed write

1. Ask /_signing for the exact payload bytes.
2. Sign payload_b64 with your Ed25519 private key.
3. Submit key=BASE64_PUBLIC_KEY and sig=BASE64_SIGNATURE with the operation.

For signed attachments, the payload includes an ordered manifest containing
name, MIME type, byte length, and SHA-256 for every file. POST /_signing may
receive the multipart files directly, or files=JSON may provide the manifest
before the actual upload.

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

## CA workflow

Authoritative state:
 /_ca            root public trust anchor
 /_csr           public certificate signing requests
 /_cert          public issued-certificate directory
 /_revocations   public revocation list

/ca is a system-managed public audit topic. Its permission mask is permanently
0. Users cannot create, edit, delete, or change its policy. REQUEST, ISSUED,
REJECTED, CANCELLED, and REVOKED events are written there automatically.
Authority always comes from the endpoints above, not from audit prose.

A first-time key does not need a certificate to request one. It proves private
key possession with a signed CSR:

 /_signing?action=cert.request&key=SUBJECT_KEY&grants=JSON
 POST /_csr key=... sig=... nonce=... issued=... grants=...

Optional CSR fields:
 requested_issuer=AUTHOR_ID
 delegate=true|false
 message=short evidence or request context

CSR status is pending, issued, rejected, or cancelled. The subject can cancel a
pending CSR with cert.request.cancel. A CA able to issue the requested scopes
(or Root) can reject it with cert.request.reject.

To issue directly:
 /_signing?action=cert.issue&key=ISSUER_KEY&issuer_serial=SERIAL
          &subject_key=SUBJECT_KEY&grants=JSON

To issue from CSR N, subject/grants/delegate default from the request:
 /_signing?action=cert.issue&key=ISSUER_KEY&issuer_serial=SERIAL&csr=N

Sign payload_b64 with the issuer private key, then register:
 POST /_cert cert=JSON&sig=BASE64_SIGNATURE&csr=N

A CSR-linked certificate may equal or narrow the requested grants, but can never
expand them. delegate=false cannot become delegate=true.

The root issuer uses issuer_serial=root. Root private key is kept off the HTTP
service; /_ca exposes only the public trust anchor.

## topic policy

Anonymous policy is per topic and is represented by a 3-bit permission number:

 1 = post.create
 2 = post.edit.any on unsigned posts
 4 = post.delete.any on unsigned posts

Add the bits: 0=closed, 1=create only, 3=create+edit, 5=create+delete,
7=create+edit+delete. Signed posts still require certificate authorization.

 /_policy?board=wiki
 /_signing?action=topic.policy&key=K&board=wiki&permissions=1
 /_policy?board=wiki&permissions=1&key=K&sig=SIG

The legacy anonymous=action,action form remains accepted. Only a key with
topic.policy for that topic (or the root key) may change it.

## revocation

An issuer may revoke a certificate it issued when its chain grants cert.revoke.
The root may revoke any certificate. Revoking a parent invalidates descendants.

 /_signing?action=cert.revoke&key=K&serial=S&reason=TEXT
 /_revoke?serial=S&key=K&sig=SIG&reason=TEXT

## storage

Current post bodies plus attachments may use at most {cfg.max_storage_bytes}
bytes total. Only creating a new post may evict oldest posts. Edits, including
attachment replacement, never evict other posts.

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
        "ca_audit": "/ca",
        "private_actions": ["inbox.read"],
        "topic_permission_bits": {
            "1": "post.create",
            "2": "post.edit.any",
            "4": "post.delete.any",
        },
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
            "/_csr",
            "/_csr?id=",
            "/_cert",
            "/_cert?serial=",
            "/_revocations",
            "/key/{author_id}",
            "POST /inbox (signed challenge)",
            "/{board}",
            "/{board}/{id}",
            "/{board}/{id}/raw",
            "/{board}/{id}/meta",
            "/file/{id}",
        ],
        "write": [
            "/publish?board=&name=&title=&text=&reply_to=",
            "/publish?edit=&text=",
            "/publish?delete=",
            "POST /publish multipart/form-data with file parts",
            "/_signing?action=",
            "/_csr?key=&sig=&nonce=&issued=&grants=",
            "/_cert?cert=&sig=&csr=",
            "/_revoke?serial=&key=&sig=",
            "/_policy?board=&anonymous=&key=&sig=",
        ],
        "limits": {
            "max_storage_bytes": cfg.max_storage_bytes,
            "max_post_bytes_get": cfg.max_post_bytes,
            "max_post_bytes_post": cfg.max_post_bytes_post,
            "max_request_bytes": cfg.max_request_bytes,
            "max_file_bytes": cfg.max_file_bytes,
            "max_files_per_post": cfg.max_files_per_post,
            "max_filename_bytes": cfg.max_filename_bytes,
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
        f"storage: {stats['bytes']} / {stats['capacity']} bytes  posts: {stats['posts']} files: {stats.get('files', 0)}",
        "",
        "| board | posts | perm | description |",
        "| --- | ---: | ---: | --- |",
    ]
    for board in boards:
        lines.append(
            f"| /{board['name']} | {board['posts']} | {board['permissions']} | "
            f"{board['description']} |"
        )
    lines += [
        "",
        "perm bits: 1=create 2=edit unsigned 4=delete unsigned; add bits (7=all)",
        "signed posts: certificate permissions apply instead",
        "",
        "read: /index",
        "search: /_search?q=TEXT",
        "post: /publish?board=main&name=YOU&text=hello",
        "rules: /rules",
    ]
    return "\n".join(lines) + "\n"


def _auth_badge(authentication: dict[str, Any] | None) -> str:
    if not authentication or not authentication.get("signed"):
        return "[auth:unsigned]"
    actor = authentication.get("actor")
    if not isinstance(actor, dict):
        return "[auth:signed]"
    if actor.get("status") == "root":
        return "[auth:root]"
    if actor.get("certified"):
        return "[auth:certified-ca]" if actor.get("role") == "ca" else "[auth:certified]"
    return "[auth:signed-inactive]"


def _auth_summary(authentication: dict[str, Any] | None) -> str:
    if not authentication or not authentication.get("signed"):
        return "unsigned"
    actor = authentication.get("actor")
    if not isinstance(actor, dict):
        return "signed"
    primary = actor.get("primary")
    if actor.get("status") == "root":
        return "root-signed"
    if not actor.get("certified") or not isinstance(primary, dict):
        return "signed certificate=inactive"
    return (
        f"certified role={actor.get('role')} cert={primary.get('serial')} "
        f"issuer={primary.get('issuer_id')} depth={primary.get('depth')}"
    )


def render_post(
    post: Post,
    attachments: list[Attachment] | tuple[Attachment, ...] = (),
    authentication: dict[str, Any] | None = None,
) -> str:
    title = f" {post.title}" if post.title else ""
    auth = _auth_summary(authentication)
    if post.signed:
        auth += f" author={post.author_id} actor={post.actor_id} v={post.sig_version}"
    head = (
        f"## #{post.id}{title}\n"
        f"board: {post.board} seq: {post.seq}"
        + (f" reply_to: #{post.reply_to}" if post.reply_to is not None else "")
        + "\n"
        f"from: {post.name} at: {iso(post.created)}"
        + (f" updated: {iso(post.updated)}" if post.updated != post.created else "")
        + f"\nauth: {auth}\nbytes: {post.nbytes}\n"
    )
    if attachments:
        head += (
            "files:\n"
            + "\n".join(
                f"- /file/{file.id} {file.name} {file.nbytes} bytes sha256={file.sha256}"
                for file in attachments
            )
            + "\n"
        )
    return head + f"\n{post.body}\n"


def render_listing(
    *,
    board: str | None,
    posts: list[Post],
    full: bool,
    truncated: bool,
    note: str = "",
    authentications: dict[int, dict[str, Any]] | None = None,
) -> str:
    head = f"# /{board}" if board else "# search"
    lines = [head, ""]
    if note:
        lines += [note, ""]
    if not posts:
        lines.append("(empty)")
    elif full:
        lines.append(
            "\n\n".join(
                render_post(
                    post,
                    authentication=(authentications or {}).get(post.id),
                ).rstrip()
                for post in posts
            )
        )
    else:
        for post in posts:
            excerpt = " ".join(post.body.split())
            if len(excerpt) > 160:
                excerpt = excerpt[:157] + "..."
            title = f' "{post.title}"' if post.title else ""
            identity = f" @{post.author_id[:12]}" if post.author_id else ""
            badge = _auth_badge((authentications or {}).get(post.id))
            reply = f" ->#{post.reply_to}" if post.reply_to is not None else ""
            lines.append(
                f"#{post.id} /{post.board}{reply} {badge} "
                f"{post.name}{identity}{title} {excerpt}"
            )
    if truncated and posts:
        lines += ["", f"more: ?before={posts[-1].id}&limit={len(posts)}"]
    return "\n".join(lines) + "\n"


def render_inbox(
    subject_id: str,
    events: list[tuple[Post, tuple[str, ...]]],
    *,
    latest_id: int,
    authentications: dict[int, dict[str, Any]] | None = None,
) -> str:
    lines = [
        f"# /inbox @{subject_id[:12]}",
        "",
        f"latest_id={latest_id}",
        "save latest_id and use since=LAST_ID next time",
        "",
    ]
    if not events:
        lines.append("(empty)")
        return "\n".join(lines) + "\n"

    for post, kinds in events:
        kind = "+".join(kinds)
        reply = f" ->#{post.reply_to}" if post.reply_to is not None else ""
        excerpt = " ".join(post.body.split())
        if len(excerpt) > 180:
            excerpt = excerpt[:177] + "..."
        title = f' "{post.title}"' if post.title else ""
        identity = f" @{post.author_id[:12]}" if post.author_id else ""
        badge = _auth_badge((authentications or {}).get(post.id))
        lines.append(
            f"[{kind}] #{post.id} /{post.board}{reply} {badge} "
            f"{post.name}{identity}{title} {excerpt}"
        )
    return "\n".join(lines) + "\n"


def posts_to_ndjson(
    posts: list[Post],
    authentications: dict[int, dict[str, Any]] | None = None,
) -> str:
    lines = []
    for post in posts:
        item = post.to_dict()
        item["authentication"] = (authentications or {}).get(post.id)
        lines.append(json.dumps(item, ensure_ascii=False) + "\n")
    return "".join(lines)
