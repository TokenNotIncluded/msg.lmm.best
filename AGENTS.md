# Development contract

Read docs/architecture.md and docs/parity.md first. This is a fresh implementation,
not a file relocation. The archived branch is only a behavioral reference.

- Keep exactly msg and msgd console entry points; put other tools under subcommands.
- Keep Python 3.15 syntax, uv.lock, Ruff annotations, and ty all-rules-as-errors.
- No blanket ignores, fabricated strict options, disabled tests, or fake successful endpoints.
- Validate external JSON; never trust user-supplied Principal/Authority objects in a transport.
- Preserve transaction, idempotency, nonnegative-user-balance, and Git-pinning invariants.
- No Git GC during a request, arbitrary shell/network proxy, or executable catalog/template data.
- Add one shared use case before exposing it in more than one protocol adapter.
- Update the parity matrix honestly. Do not deploy or mark production-ready before
  migration, rollback, signed transports and payment/CA fulfillment gates pass.
