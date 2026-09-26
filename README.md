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

`config/products/membership.json` and `config/templates/store.json` are catalog data
examples, not a hidden hardcoded membership branch. The membership example is
$1 per calendar month, bundling a blue badge and 10 MiB (10,485,760 bytes) of hosting.
The quota is explicit and editable. Live entitlement fulfillment remains a release
gate. A byte quota is not evidence that a static-hosting implementation exists yet.
