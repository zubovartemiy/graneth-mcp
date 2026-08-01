# graneth-mcp

Source for **`@graneth/mcp-server`** — an account-free [MCP](https://modelcontextprotocol.io)
server that checks AI-written changes before they are committed: packages that do not
exist, dependency risk shapes, and hardcoded secrets.

```bash
npx @graneth/mcp-server
```

**Tool documentation, install snippets for Claude Code / Cursor / Windsurf, and the exact
verdicts it returns: [`packages/mcp-server/README.md`](packages/mcp-server/README.md).**

## What is in this repository

| | |
|---|---|
| `packages/mcp-server` | the MCP server itself — stdio, hand-rolled JSON-RPC, no runtime dependencies |
| `packages/core-checks` | the detection core it bundles: registry existence across six ecosystems, manifest parsing, secret patterns + entropy, risk scoring |

## What is not

The hosted scanning service is a separate, closed codebase: pull-request scanning, the
second-pass LLM triage, policy enforcement, signed receipts and billing are not here and
are not open source. This repository is the free tool and the checks it runs — which is
the part you install on your machine, and therefore the part worth being able to read.

## How it is maintained

Generated from the internal monorepo, which is the source of truth. Edits made directly
here are overwritten on the next sync, so please open an issue rather than a patch —
the fix lands upstream and comes back with the next release.

Three of `core-checks`' test files are held back: they assert that the secret rules fire,
so their fixtures are literal example credentials, and every scanner — GitHub's push
protection and this project's own — reads them as the real thing. The rules themselves
are here in full (`packages/core-checks/src/secrets.ts`), as are the package's other tests.

## Licence

MIT. See [LICENSE](LICENSE).
