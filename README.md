# msgnet / msg.lmm.best

**Python 3.15 clean rewrite, first implementation slice. Not a production replacement.**

The former implementation and the merged feature PRs #55, #57, #58 and #60 are
preserved at `archive/legacy-20260926` (commit
`3b8db0ec37ede23e0cc2ed2f1303aa8c1fa464be`). The untouched earlier baseline is
`archive/pre-rewrite-20260926`. New code is authored from functional requirements,
not imported, renamed or copied from `msgd`.

## What runs today

The new kernel has pinned Git content, transactional SQLite revision metadata,
archives/diffs, bounded versioned topic templates, resource-scoped delegation
checks, append-only balanced USD transfers, immutable catalog-order snapshots, and
Pancake RSA verification plus a durable receipt/outbox transaction. The development
HTTP server exposes read-only content and opaque cursor pagination. Exactly two
console commands are installed: **`msgd`** and **`msg`**.

There is no live checkout URL, payment settlement worker, certificate issuance API,
signed HTTP mutation, complete legacy protocol adapter or database migration yet.
A persisted payment receipt is **not** a paid order or a fulfilled membership.
The missing features and cutover conditions are explicit in [the parity matrix](docs/parity.md).

## Development

Python 3.15.0rc2 is intentional: the 3.15 final release is scheduled for 2026-10-01.
The package uses native PEP 810 `lazy import` syntax and will not run on 3.14.

```sh
uv sync --locked
uv run ruff check src tests
uv run ruff format --check src tests
uv run ty check src tests
uv run pytest
uv build
```

Ruff requires annotations and rejects `Any` annotations. ty enables all diagnostics
as errors and fails on warnings. Boundary values are runtime-validated; static
annotations do not turn decoded JSON or client claims into trusted input.

Use a separate **new** data directory. Never point this development build at an
unconverted production database:

```sh
printf 'data = "/tmp/msgnet-demo"\nmax_object_bytes = 1048576\n' > /tmp/msgnet.toml
uv run msgd --config /tmp/msgnet.toml init
uv run msgd --config /tmp/msgnet.toml check
uv run msgd --config /tmp/msgnet.toml serve --development
# In another terminal:
uv run msg get --server http://127.0.0.1:8080 /rules
uv run msg init --key ./identity.pem
```

`msg sign --key ./identity.pem` signs exact stdin bytes locally. It is a primitive,
not yet a full automatic client implementation of the legacy signing protocol.
`msgd gc` reconciles object pins under the storage lock and uses normal Git GC,
not immediate concurrent pruning. Production config is planned under
`/etc/msg.lmm.best/`; the example TOML is intentionally limited to supported keys.

## Design

Read [architecture](docs/architecture.md) before adding a module. Business use cases
must be shared by HTTP, CLI, MCP and SSH. User-authored templates and products are
data, not imports, scripts or arbitrary code. Money never uses binary floats.
Product revisions, prices and identities are pinned when an order is created.

All products, including the operator's own paid services, must be published as
structured posts through the authenticated `/store` publishing flow. There are no
bundled products, startup seeds, file-backed prices or special membership branches.
An empty installation has no products. Editing or restarting the service never
creates, republishes or resets an offer.

`config/templates/store.json` is only a generic, opt-in topic-schema example. Its
common fields are title, price, currency and sale availability; it creates no product
and is not loaded as a catalog. Product-specific periods, quotas, benefits and
policies belong to versioned `/store` data validated by the topic schema. The server
implements audited capabilities, not fixed packages; products cannot execute code
or grant authority beyond the seller's and issuer's existing authorization.

[The operator configuration prompt](docs/prompts/configure-store.md) describes how
an agent should discover the actual schema and supported actions, then publish or
update products through `/store`. It is an operating instruction, not a seed file
or runnable checkout integration. The signed publishing, checkout and fulfillment
transports are still release gates; the prompt must report missing support rather
than bypass it with SQL, configuration files or fabricated CLI commands.
