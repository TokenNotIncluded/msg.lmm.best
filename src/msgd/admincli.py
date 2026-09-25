"""Root/super-admin CLI for msg.lmm.best."""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.certcli import DEFAULT_API, DEFAULT_PRIVATE, _load_private, _public_b64, _sign_b64
from msgd.crypto import public_identity

CSR_REF_RE = re.compile(r"csr=/_csr\?id=(\d+)")
CA_POST_RE = re.compile(r"(?:^|/)ca/(\d+)(?:/|$)")
CSR_QUERY_RE = re.compile(r"(?:^|[?&])id=(\d+)(?:&|$)")


class AdminError(RuntimeError):
    pass


@dataclass
class Api:
    base: str = DEFAULT_API
    timeout: int = 15

    def _request(
        self,
        path: str,
        fields: dict[str, str] | None = None,
        *,
        method: str = "GET",
    ) -> str:
        url = self.base.rstrip("/") + path
        data = None
        headers: dict[str, str] = {}
        if fields:
            encoded = urlencode(fields)
            if method == "GET":
                url += ("&" if "?" in url else "?") + encoded
            else:
                data = encoded.encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            raise AdminError(f"HTTP {exc.code}: {body.strip()}") from exc
        except URLError as exc:
            raise AdminError(f"cannot reach {url}: {exc.reason}") from exc

    def get(self, path: str, fields: dict[str, str] | None = None) -> str:
        return self._request(path, fields, method="GET")

    def post(self, path: str, fields: dict[str, str]) -> str:
        return self._request(path, fields, method="POST")

    def json_get(self, path: str, fields: dict[str, str] | None = None) -> Any:
        try:
            return json.loads(self.get(path, fields))
        except json.JSONDecodeError as exc:
            raise AdminError(f"expected JSON from {path}") from exc

    def json_post(self, path: str, fields: dict[str, str]) -> Any:
        try:
            return json.loads(self.post(path, fields))
        except json.JSONDecodeError as exc:
            raise AdminError(f"expected JSON from {path}") from exc


def _identity(key: Ed25519PrivateKey) -> tuple[str, str]:
    public = _public_b64(key)
    _, author_id = public_identity(public)
    return public, author_id


def _payload_signature(key: Ed25519PrivateKey, payload_b64: str) -> str:
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except ValueError as exc:
        raise AdminError("server returned invalid payload_b64") from exc
    return _sign_b64(key, payload)


def _parse_grants(values: list[str] | None) -> list[dict[str, object]] | None:
    if not values:
        return None
    grants: dict[str, set[str]] = {}
    for value in values:
        if "=" not in value:
            raise AdminError("--grant must be TOPIC=action,action")
        topic, raw_actions = value.split("=", 1)
        topic = topic.strip()
        actions = {item.strip() for item in raw_actions.split(",") if item.strip()}
        if not topic or not actions:
            raise AdminError("--grant must include a topic and at least one action")
        grants.setdefault(topic, set()).update(actions)
    return [
        {"topic": topic, "actions": sorted(actions)} for topic, actions in sorted(grants.items())
    ]


def _numeric_token(value: str) -> int | None:
    stripped = value.strip()
    if stripped.startswith("#"):
        stripped = stripped[1:]
    if stripped.isdigit():
        number = int(stripped)
        return number if number > 0 else None
    return None


def resolve_csr(api: Api, value: str) -> int:
    """Resolve CSR id, /_csr?id=N, /ca/N, or a bare CA audit-post id."""
    token = value.strip()
    parsed = urlparse(token)

    # Explicit CSR references always win.
    if token.startswith("csr:"):
        number = _numeric_token(token[4:])
        if number is None:
            raise AdminError("invalid csr:ID reference")
        api.json_get("/_csr", {"id": str(number)})
        return number
    if "_csr" in parsed.path or token.startswith("/_csr"):
        match = CSR_QUERY_RE.search(parsed.query or token)
        if not match:
            raise AdminError("CSR URL must include id=N")
        number = int(match.group(1))
        api.json_get("/_csr", {"id": str(number)})
        return number

    # Explicit /ca/N references are audit-post ids.
    explicit_post = token.startswith("post:") or bool(CA_POST_RE.search(parsed.path or token))
    if token.startswith("post:"):
        number = _numeric_token(token[5:])
    else:
        match = CA_POST_RE.search(parsed.path or token)
        number = int(match.group(1)) if match else _numeric_token(token)

    if number is None:
        raise AdminError("expected CSR id, /_csr?id=N, or /ca/POST_ID")

    # A bare integer is intentionally post-first: admins usually copy the visible
    # /ca post id. Only accept the post interpretation when the returned global
    # post id matches the number, avoiding accidental seq-number resolution.
    try:
        meta = api.json_get(f"/ca/{number}/meta")
        if isinstance(meta, dict) and int(meta.get("id", -1)) == number:
            body = str(meta.get("body") or "")
            match = CSR_REF_RE.search(body)
            if match:
                csr_id = int(match.group(1))
                api.json_get("/_csr", {"id": str(csr_id)})
                return csr_id
            if explicit_post:
                raise AdminError(f"/ca/{number} is not a certificate request audit post")
    except AdminError:
        if explicit_post:
            raise

    # Otherwise treat the number as the structured CSR id.
    api.json_get("/_csr", {"id": str(number)})
    return number


def approve(
    api: Api,
    key: Ed25519PrivateKey,
    reference: str,
    *,
    issuer_serial: str = "root",
    grants: list[dict[str, object]] | None = None,
    delegate: bool | None = None,
    days: int = 365,
) -> dict[str, Any]:
    csr_id = resolve_csr(api, reference)
    csr = api.json_get("/_csr", {"id": str(csr_id)})
    if csr.get("status") != "pending":
        raise AdminError(f"CSR #{csr_id} is {csr.get('status')}, not pending")
    if days < 1:
        raise AdminError("--days must be >= 1")

    public, author_id = _identity(key)
    requested = str(csr.get("requested_issuer") or "")
    if requested and requested != author_id:
        raise AdminError(f"CSR #{csr_id} requested issuer {requested}; this key is {author_id}")

    now = int(time.time())
    fields = {
        "action": "cert.issue",
        "key": public,
        "csr": str(csr_id),
        "issuer_serial": issuer_serial,
        "not_before": str(now - 60),
        "not_after": str(now + days * 86400),
    }
    if grants is not None:
        fields["grants"] = json.dumps(grants, separators=(",", ":"))
    if delegate is not None:
        fields["delegate"] = "true" if delegate else "false"

    signing = api.json_get("/_signing", fields)
    result = api.json_post(
        "/_cert",
        {
            "csr": str(csr_id),
            "cert": str(signing["certificate"]),
            "sig": _payload_signature(key, str(signing["payload_b64"])),
        },
    )
    return result


def reject(
    api: Api,
    key: Ed25519PrivateKey,
    reference: str,
    *,
    reason: str = "",
) -> dict[str, Any]:
    csr_id = resolve_csr(api, reference)
    public, _ = _identity(key)
    signing = api.json_get(
        "/_signing",
        {
            "action": "cert.request.reject",
            "key": public,
            "id": str(csr_id),
            "reason": reason,
        },
    )
    return api.json_post(
        "/_csr",
        {
            "reject": str(csr_id),
            "key": public,
            "sig": _payload_signature(key, str(signing["payload_b64"])),
            "reason": reason,
        },
    )


def revoke(
    api: Api,
    key: Ed25519PrivateKey,
    serial: str,
    *,
    reason: str = "",
) -> str:
    public, _ = _identity(key)
    signing = api.json_get(
        "/_signing",
        {
            "action": "cert.revoke",
            "key": public,
            "serial": serial,
            "reason": reason,
        },
    )
    return api.post(
        "/_revoke",
        {
            "serial": serial,
            "key": public,
            "sig": _payload_signature(key, str(signing["payload_b64"])),
            "reason": reason,
        },
    )


def set_policy(api: Api, key: Ed25519PrivateKey, board: str, permissions: int) -> dict[str, Any]:
    if not 0 <= permissions <= 7:
        raise AdminError("permissions must be between 0 and 7")
    public, _ = _identity(key)
    fields = {
        "action": "topic.policy",
        "key": public,
        "board": board,
        "permissions": str(permissions),
    }
    signing = api.json_get("/_signing", fields)
    return api.json_post(
        "/_policy",
        {
            "board": board,
            "permissions": str(permissions),
            "key": public,
            "sig": _payload_signature(key, str(signing["payload_b64"])),
        },
    )


def delete_post(api: Api, key: Ed25519PrivateKey, post_id: int) -> str:
    public, _ = _identity(key)
    signing = api.json_get(
        "/_signing",
        {
            "action": "post.delete",
            "key": public,
            "id": str(post_id),
        },
    )
    return api.post(
        "/publish",
        {
            "delete": str(post_id),
            "key": public,
            "sig": _payload_signature(key, str(signing["payload_b64"])),
        },
    )


def _fmt_subject(value: str) -> str:
    return value if len(value) <= 18 else value[:12] + "…" + value[-4:]


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def command_status(args: argparse.Namespace) -> int:
    api = Api(args.api)
    health = api.get("/_health").strip()
    root = api.json_get("/_ca")
    pending = api.json_get("/_csr", {"status": "pending", "limit": "100"})
    print(health)
    print(f"root_id={root['root_id']}")
    print(f"pending_csrs={len(pending)}")
    return 0


def command_pending(args: argparse.Namespace) -> int:
    api = Api(args.api)
    rows = api.json_get("/_csr", {"status": "pending", "limit": str(args.limit)})
    if not rows:
        print("(no pending CSRs)")
        return 0
    print("REF       SUBJECT             ISSUER              D  GRANTS")
    for row in rows:
        grants = json.dumps(row.get("grants", []), ensure_ascii=False, separators=(",", ":"))
        issuer = str(row.get("requested_issuer") or "any")
        print(
            f"{('csr:' + str(row['id'])):<9} {_fmt_subject(str(row['subject_id'])):<19} "
            f"{_fmt_subject(issuer):<19} {int(bool(row.get('delegate')))}  {grants}"
        )
    return 0


def command_show(args: argparse.Namespace) -> int:
    api = Api(args.api)
    csr_id = resolve_csr(api, args.reference)
    _print_json(api.json_get("/_csr", {"id": str(csr_id)}))
    return 0


def command_approve(args: argparse.Namespace) -> int:
    api = Api(args.api)
    key = _load_private(args.key)
    grants = _parse_grants(args.grant)
    result = approve(
        api,
        key,
        args.reference,
        issuer_serial=args.issuer_serial,
        grants=grants,
        delegate=args.delegate,
        days=args.days,
    )
    print(f"approved csr={result.get('csr')} serial={result['serial']}")
    print(f"subject_id={result['subject_id']}")
    return 0


def command_reject(args: argparse.Namespace) -> int:
    api = Api(args.api)
    key = _load_private(args.key)
    result = reject(api, key, args.reference, reason=args.reason)
    print(f"rejected csr={result['id']} subject={result['subject_id']}")
    if args.reason:
        print(f"reason={args.reason}")
    return 0


def command_certs(args: argparse.Namespace) -> int:
    api = Api(args.api)
    fields = {"limit": str(args.limit)}
    if args.issuer:
        fields["issuer"] = args.issuer
    rows = api.json_get("/_cert", fields)
    if not rows:
        print("(no certificates)")
        return 0
    print("SERIAL                            SUBJECT             ISSUER              ACTIVE")
    for row in rows:
        serial = str(row["serial"])
        subject = _fmt_subject(str(row["subject_id"]))
        issuer = _fmt_subject(str(row["issuer_id"]))
        active = api.json_get("/_cert", {"serial": serial}).get("active")
        print(f"{serial:<32} {subject:<19} {issuer:<19} {str(bool(active)).lower()}")
    return 0


def command_revoke(args: argparse.Namespace) -> int:
    api = Api(args.api)
    key = _load_private(args.key)
    print(revoke(api, key, args.serial, reason=args.reason).strip())
    return 0


def _parse_home_policies(home: str) -> list[tuple[str, int, int, str]]:
    rows: list[tuple[str, int, int, str]] = []
    pattern = re.compile(r"^\| /([^ |]+) \| (\d+) \| (\d+) \| (.*?) \|$")
    for line in home.splitlines():
        match = pattern.match(line)
        if match:
            rows.append(
                (
                    match.group(1),
                    int(match.group(2)),
                    int(match.group(3)),
                    match.group(4),
                )
            )
    return rows


def command_policies(args: argparse.Namespace) -> int:
    api = Api(args.api)
    rows = _parse_home_policies(api.get("/"))
    if not rows:
        raise AdminError("could not parse topic policy table from homepage")
    print("TOPIC            POSTS  PERM  DESCRIPTION")
    for topic, posts, perm, description in rows:
        print(f"/{topic:<15} {posts:<6} {perm:<5} {description}")
    print("bits: 1=create 2=edit unsigned 4=delete unsigned")
    return 0


def command_policy_set(args: argparse.Namespace) -> int:
    api = Api(args.api)
    key = _load_private(args.key)
    result = set_policy(api, key, args.board, args.permissions)
    print(f"/{result['board']} permissions={result['permissions']} version={result['version']}")
    return 0


def command_delete_post(args: argparse.Namespace) -> int:
    if not args.yes:
        raise AdminError("delete is irreversible; pass --yes")
    api = Api(args.api)
    key = _load_private(args.key)
    print(delete_post(api, key, args.post_id).strip())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="msgd-admin",
        description="Root/super-admin commands for msg.lmm.best",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="show server, Root CA, and pending CSR status")
    status.add_argument("--api", default=DEFAULT_API)
    status.set_defaults(func=command_status)

    pending = sub.add_parser("pending", help="list pending certificate requests")
    pending.add_argument("--api", default=DEFAULT_API)
    pending.add_argument("--limit", type=int, default=50)
    pending.set_defaults(func=command_pending)

    show = sub.add_parser("show", help="show a CSR; accepts CSR id or /ca audit post id")
    show.add_argument("reference")
    show.add_argument("--api", default=DEFAULT_API)
    show.set_defaults(func=command_show)

    approve_p = sub.add_parser("approve", help="approve a CSR or /ca request-post id")
    approve_p.add_argument("reference")
    approve_p.add_argument("--api", default=DEFAULT_API)
    approve_p.add_argument("--key", default=DEFAULT_PRIVATE)
    approve_p.add_argument("--issuer-serial", default="root")
    approve_p.add_argument("--grant", action="append", help="narrow grant: TOPIC=action,action")
    approve_p.add_argument("--delegate", action=argparse.BooleanOptionalAction, default=None)
    approve_p.add_argument("--days", type=int, default=365)
    approve_p.set_defaults(func=command_approve)

    reject_p = sub.add_parser("reject", help="reject a CSR or /ca request-post id")
    reject_p.add_argument("reference")
    reject_p.add_argument("--api", default=DEFAULT_API)
    reject_p.add_argument("--key", default=DEFAULT_PRIVATE)
    reject_p.add_argument("--reason", default="")
    reject_p.set_defaults(func=command_reject)

    certs = sub.add_parser("certs", help="list issued certificates")
    certs.add_argument("--api", default=DEFAULT_API)
    certs.add_argument("--issuer", default="")
    certs.add_argument("--limit", type=int, default=50)
    certs.set_defaults(func=command_certs)

    revoke_p = sub.add_parser("revoke", help="revoke a certificate")
    revoke_p.add_argument("serial")
    revoke_p.add_argument("--api", default=DEFAULT_API)
    revoke_p.add_argument("--key", default=DEFAULT_PRIVATE)
    revoke_p.add_argument("--reason", default="")
    revoke_p.set_defaults(func=command_revoke)

    policies = sub.add_parser("policies", help="show all topic permission masks")
    policies.add_argument("--api", default=DEFAULT_API)
    policies.set_defaults(func=command_policies)

    policy_set = sub.add_parser("policy-set", help="set topic anonymous permission mask")
    policy_set.add_argument("board")
    policy_set.add_argument("permissions", type=int)
    policy_set.add_argument("--api", default=DEFAULT_API)
    policy_set.add_argument("--key", default=DEFAULT_PRIVATE)
    policy_set.set_defaults(func=command_policy_set)

    delete = sub.add_parser("delete-post", help="irreversibly delete any post as Root")
    delete.add_argument("post_id", type=int)
    delete.add_argument("--api", default=DEFAULT_API)
    delete.add_argument("--key", default=DEFAULT_PRIVATE)
    delete.add_argument("--yes", action="store_true")
    delete.set_defaults(func=command_delete_post)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (AdminError, OSError, ValueError, KeyError) as exc:
        print(f"msgd-admin: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
