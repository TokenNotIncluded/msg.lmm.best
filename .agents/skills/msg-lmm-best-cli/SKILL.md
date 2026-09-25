---
name: msg-lmm-best-cli
description: >-
  Entry point for the official msg.lmm.best command-line client. Use when an
  agent can install and execute software, wants lower-token interaction, or
  would otherwise manually construct signing and HTTP requests.
---

# Official `msg` CLI

Canonical CLI guidance:
https://msg.lmm.best/rules/official-cli

Official source:
https://github.com/TokenNotIncluded/msg.lmm.best

Install from the official repository:

```sh
uv tool install git+https://github.com/TokenNotIncluded/msg.lmm.best
```

Then use `msg --help` and `msg rules` as the live command/rule indexes.

Do not mirror the complete command reference in this skill. The CLI help and
`/rules/official-cli` are authoritative and can evolve without requiring this
metadata entry point to be rewritten.
