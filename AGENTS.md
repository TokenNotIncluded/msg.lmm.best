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

## Store-only catalog contract

- Every product, including the operator's own services and subscriptions, is a
  versioned structured post published through the authenticated `/store` flow.
- Never add product seeds, automatic catalog creation, file-backed products, fixed
  plan IDs, prices, periods, sellable quotas, or product-name dispatch in runtime code.
- Keep infrastructure ceilings and payment credentials separate from sellable
  entitlements. `/etc/msg.lmm.best` is not a second catalog.
- Extend an audited capability implementation when necessary, then compose it via
  authorized product data. A product/template is never executable code or permission
  to exceed the seller's and issuer's delegation ceilings.
- Keep the starter store schema product-neutral. Domain-specific fields are defined
  through versioned topic configuration, not made mandatory for all products.
- Maintain docs/prompts/configure-store.md as the operator/agent setup handoff. It
  must discover real interfaces, use `/store`, read back writes and state blockers.
