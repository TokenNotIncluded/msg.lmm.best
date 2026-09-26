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
| Catalog | All products published through `/store`, including operator services; empty startup catalog; no product seeds/config catalog; neutral versioned schema; `/ads` certificate-gated publishing | Kernel source/snapshot tests; signed publishing and operator configuration workflow end-to-end pending |
| Payments | Pancake signed checkout, expiring link, verified durable callback, payment/period correlation, limited online CA, reversal reconciliation | Signature/receipt tests first; live integration pending |
| Entitlements / subscriptions | Product-defined periods, quotas and capability bundles; certificate-backed display badges and scoped grants; no built-in plans | Generic fulfillment, renewals/expiry/reversal and seller/issuer authority checks pending |
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

Product configuration is an operational step, not application source code. Use
[prompts/configure-store.md](prompts/configure-store.md) with the operator's product
table only after the required publishing, schema and fulfillment interfaces exist.
A stored draft, verified receipt or data-only benefit is not a working paid service.
