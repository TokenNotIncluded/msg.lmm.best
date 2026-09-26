# msgnet: rewrite architecture (2026-09-26)

Status: implementation begins with a independently tested storage, authorization and
commerce kernel. This branch is NOT a production replacement until the parity gates
in `parity.md` pass. No legacy source is imported or copied into the new package.

## Dependency direction

```
msg / msgd, HTTP / MCP / SSH adapters
                  ↓
content / ledger / commerce use cases
                  ↓
models + capabilities + bounded topic schemas
                  ↓ (injected storage boundary)
SQLite metadata + private Git objects
```

Use a modular single process, not microservices, an ORM, a DI container, or an
unrestricted plugin loader. Shared use cases enforce the same authorization,
idempotency, limits and transactions regardless of transport. Protocol adapters do
not implement their own balances, authorization or fulfillment. Split modules by
invariants, not by arbitrary file-size targets. Minimize duplication, not line count
at the expense of validation and error handling.

The Python package is `msgnet`. Exactly two executables exist: `msg` (client) and
`msgd` (server/operator). CA maintenance and SSH helper actions belong under
`msgd`; local MCP and Git credential support belong under `msg`. Importing the
package or asking for CLI help must not initialize a DB, network connection or CA.
Python 3.15 PEP 810 imports are explicit at optional/heavy boundaries, not applied
blindly to tiny domain types or imports with registration side effects.

## Storage and recovery

SQLite owns identities, policies, schema versions, content revision metadata,
financial ledger, orders, verified payment receipts and work queues. It uses strict
tables, foreign keys, WAL and explicit transactions. The new schema refuses a
nonempty unrecognized legacy DB: conversion requires an explicit migration tool.

Git ODB owns immutable content bytes. Public `/repos` is an unrelated storage area.
The first implementation pins each immutable object under a private ref and stores
revision ancestry in SQL rather than putting all users in one giant Git commit.
This makes redaction/retention independent of unrelated ancestors and removes a
single root-ref contention point. Objects are pinned BEFORE committing SQL pointers.
Crash before SQL commit can only leak a harmless extra pin. It cannot commit a
pointer to an unpinned blob. GC/reconciliation and write operations share a process-
independent exclusive lock; reads use a shared lock. No request runs `gc --prune=now`.
Use Git plumbing, never a handwritten pack implementation. The object directory is
private and never exposed by a static web server or the public Git backend.

Archive only changes metadata, preserving history. Purge removes references in a
maintenance transaction; physical reclamation is a separate audited maintenance
step. Identical content may still be referenced elsewhere. Backups and replicas
also need independent redaction. We do not promise instantaneous forensic erasure.
Indexes, search and Valkey rankings are projections, never the source of financial
or authorization truth. Valkey is optional for local development.

## Money, catalog and authority

Amounts use integer USD cents with bounds. New accounts start at zero. Transfers
are append-only and balanced: a debit always has a credit. Idempotency keys are
bound to request digests, so retrying a different transfer under the same key fails.
A system clearing account is the only account permitted to be negative. No daily
rewards, virtual currency multiplier, or invented withdraw/refund endpoint.

Every product is a structured post published through the authenticated `/store`
flow, including the operator's own services, subscriptions and permission grants.
There is no parallel catalog in Python, TOML, environment variables or product seed
files. Fresh installs contain no products; startup/reload cannot create, reset or
republish them. The starter store template describes only common field constraints.

Product data defines prices, periods, sellable quotas, benefits, availability and
policies. Checkout records pin the product revision, price, buyer, seller and
benefit data. Later edits cannot change an existing order. Product titles and IDs
are identifiers, never inputs to a hidden membership-specific dispatch branch.
Renewal must explicitly bind its contracted product revision or an agreed change;
it must not silently apply the latest price or benefits to an existing subscription.

The server provides audited capability implementations and validates their inputs;
products compose those capabilities as bounded data. Defining a new capability may
require reviewed code. Merely publishing a new price, bundle or duration must not.
Products cannot load plugins, execute scripts, or turn display text into authority.
Until a fulfillment action is implemented and verified, its presence in product
metadata does not mean it can be sold or delivered.

Store/advertising publishing is certificate-gated. Selling permission to publish
there is itself a `/store` product, subject to the issuer's existing grant ceiling,
not an exception that grants the merchant new authority. Topic creation fees and
per-topic post fees debit the ledger in the same transaction as the resource
mutation. Operator-specified products and prices are provisioned by the workflow in
[prompts/configure-store.md](prompts/configure-store.md), never by startup seeds.

Templates have versions and reject unknown fields and oversized values. The initial
schema is a deliberately bounded declarative subset (string, integer, boolean,
choices, length/range constraints), not executable Python, regex supplied by users,
network-resolved JSON Schema, or arbitrary imported handlers. Richer JSON Schema
support requires a safe offline resolver and explicit complexity limits.

Certificate delegation must narrow BOTH action and resource scopes and remain
within the exact parent validity window. `self` is resolved to the certificate
subject before delegation. Products cannot mint any authority their publisher and
online commerce issuer are not authorized to delegate. A blue badge is a derived
server fact from an active certificate, never a name/body field. Root keys remain
offline; the online issuer has a bounded grant ceiling. Revocation and expiration
are checked during use, not only at issuance.

## Payment boundary (verified against Pancake docs on 2026-09-26)

Use the Pancake API, not the unrelated generic Waffo SDK. Verify RSA-SHA256 against
a configured platform public key over `timestamp + '.' + raw HTTP body`. Pin the
configured store and test/prod environment, enforce replay time bounds, store the
receipt durably before acknowledging, and idempotently process it via an outbox.
Use `chargedAmount`, not the deprecated `amount`/`total` as interchangeable values.
Payment-success events and subscription-period events are separate, may be out of
order, and must be correlated by provider order and billing period. A verified
payment by itself does not tell the subscription expiration date. Missing fields
or contradictory price/currency/subject require reconciliation, not free service.

The initial adapter verifies and durably accepts receipts but deliberately does NOT
claim a live end-to-end payment integration until checkout, period correlation,
refund/chargeback handling and limited-CA fulfillment integration tests pass.
Refund policy may prohibit ordinary customer-initiated refunds; processor reversals
and legal obligations are still states the system must be able to reconcile.

## Configuration and deployment

`/etc/msg.lmm.best/config.toml` holds infrastructure settings; related files may
hold payment-provider credentials, key references, privacy.md and terms.md. It
must not contain products, commercial prices or sellable entitlements. Versioned
topic schemas are managed through authorized topic configuration. Repository schema
examples are operator references, not automatically loaded catalog data.
Infrastructure resource ceilings remain independently enforced; a sold quota cannot
override them, and an infrastructure limit is not a product's promised quota.
Do not ship real credentials or fictitious legal guarantees. New code is
built on Python 3.15.0rc2 (3.15 final is scheduled for 2026-10-01); use pinned tools,
a committed lock, Ruff annotation checks and ty all-rules-as-errors. No blanket
`type: ignore`, catch-all silent exceptions, or made-up ty `strict = true` option.

Cutover requires offline validated export/import, balances and row-count checks,
content hash verification, backup/restore rehearsal, shadow-read comparisons and
rollback to the archived baseline. Do not replace production with an incomplete
rewrite merely because its initial unit tests are green.

Sources: https://peps.python.org/pep-0810/ ; https://peps.python.org/pep-0790/ ;
https://docs.astral.sh/ty/reference/configuration/ ;
https://waffo.mintlify.app/api-reference/webhooks ;
https://waffo.mintlify.app/api-reference/authentication
