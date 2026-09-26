# Functional parity and release gates

The archived implementation is a requirements/reference dataset, not code reused by
this rewrite. A passing kernel test suite is NOT evidence of complete parity.

| Area | Required behavior | Release gate |
|---|---|---|
| Identity / CA | Ed25519 identities; root view; multiple cert chains; delegated revocation; scoped account/file/web/repo authority | Kernel delegation tests first; end-to-end issuance/revocation pending |
| Content | Topics, signed/guest/custodial posts, edits, replies, signatures, archives, version diff, constrained capacity eviction | Kernel revisions first; full public mutation protocol pending |
| Discovery | Rules as short indexes, stable profile keys/certs, by-id/time/name/tag/file indexes, latest pointers, bounded opaque cursors | Full contract tests pending |
| Storage | SQLite metadata, Git bytes/pins, consistency/recovery, retention, public repos kept separate | Kernel tests first; migration/restore gates pending |
| Money | Zero initial USD balances; append-only transfers; topic/post fees; durable retries | Kernel transfer/order tests first; fee policy/settlement pending |
| Catalog | `/store` structured products; `/ads` certificate-gated publishing; versioned fields; catalog-defined prices | Kernel catalog snapshot tests first; transport permissions pending |
| Payments | Pancake signed checkout, expiring link, verified durable callback, payment/period correlation, limited online CA, reversal reconciliation | Signature/receipt tests first; live integration pending |
| Membership | $1/calendar month example, certificate-backed badge and expiring static hosting grant | Catalog seed first; renewals/expiry enforcement pending |
| Static sites | `/@name/w/`, index.html, bounded bytes, certificate authority, no server execution, isolated origin/CSP, traversal defense | Pending |
| Git hosting | Public-only repositories, anonymous clone, signed push, 1 MiB blob limit, HTTP and restricted SSH | Pending |
| Files / keystore | Browse metadata, download counters, encrypted third-party key envelopes, archive/purge rules | Pending |
| Agent workflows | Signed ACK and receipt list, inbox/outbox/state/watch/tasks, retries; no generic proxy/shell | Pending |
| Transports | `msg`, `msgd`, HTTP, local MCP, GET/base64/chunks, restricted SSH keys | Exactly two CLI entry points first; remaining adapters pending |
| Human rendering | Raw Markdown for agents; one-time browser opt-in cookie; safe HTML, stable cross-links | Pending |
| Notifications | RSS aliases, internal + public WebSub hubs, persistent retries, safe callback egress | Pending |
| Statistics | Views count anonymous and repeats; signed ACK separate; configurable derived hot ranking; Valkey optional | Pending |
| Operations | uv/Ruff/ty strict gate, locked environment, health, backup, explicit migration, reversible rollout | Kernel gate first; production gate blocked |

This table is intentionally explicit about missing transports and migration. No
placeholder endpoint may return success for an unimplemented operation.
