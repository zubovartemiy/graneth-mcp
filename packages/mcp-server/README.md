# @graneth/mcp-server

An **account-free** [Model Context Protocol](https://modelcontextprotocol.io) server that
catches **AI-hallucinated dependencies** and **hardcoded secrets** in your staged
changes **before you commit** — straight inside your AI coding agent.

**Zero runtime dependencies** (verify: `npm view @graneth/mcp-server dependencies`). A
supply-chain security tool should be auditable in full — so the MCP/JSON-RPC layer is a
small hand-rolled core, not a framework, and `npm audit` on a fresh install is clean.

It exposes a single, always-free tool over stdio:

### `pre_flight_check`

Give it your staged files (path + content). It will:

- **Detect hallucinated / slopsquatted packages** — every package referenced in
  import statements **and declared in manifests** (`package.json`,
  `requirements*.txt`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`) is
  checked **live** against six registries: npm, PyPI, crates.io, RubyGems, the
  Go module proxy, and Packagist. A package that doesn't exist (404) is the
  hallmark of an AI-invented dependency an attacker may have pre-registered.
  → **BLOCKED**. A manifest that cannot be parsed is reported, never silently
  skipped, and an unreachable registry is reported as "could not verify" —
  never as clean. → **REVIEW_REQUIRED**.
- **Catch KNOWN hallucinated names — even after an attacker registers them.**
  A bundled snapshot of Graneth's public threat feed (curated + community
  tiers) is checked locally, with no network call. This is the case a live
  existence check cannot see: once a slopsquatter registers the name, the
  package *exists* — but the shared list keeps it **BLOCKED**. Community
  reports (see `report_hallucination` below) ship to every user at the next
  release.
- **Flag brand-new packages** (published < 30 days ago) — the prime
  slopsquatting attack window. → **REVIEW_REQUIRED**.
- **Risk-score the dependencies your AI agent introduced** — existence is only
  the start. A *real* package can still carry the shape attackers exploit:
  brand-new **and** running an install script **and** near-zero adoption **and**
  no provenance attestation. None of those trips a single alarm; compounded they
  do. An advisory `dependency_risk_shape` warning surfaces that stacked shape at
  generation time — explicitly a risk **assessment**, never a malware claim.
  → **REVIEW_REQUIRED**.
- **Catch hardcoded secrets** — known credential patterns (AWS, GitHub, Slack,
  OpenAI `sk-…`/`sk-proj-…`, Anthropic `sk-ant-…`, Stripe `sk_live_…`, PEM
  private keys) plus Shannon-entropy analysis with semantic variable-name
  context. → **BLOCKED** / **REVIEW_REQUIRED**. Vendor-documented sample keys
  and secrets in test/fixture files are downgraded to warnings — surfaced, but
  they won't block a commit.

No Graneth account, API key, or hosted backend is required. The checks run
locally; the only network calls are to the public package registries
(npm, PyPI, crates.io, RubyGems, proxy.golang.org, Packagist).

## Install / run

```bash
npx -y @graneth/mcp-server
```

## Configure your agent

Most clients take this exact JSON block; only the file it goes in (or the CLI
command) differs. Codex is the exception — it configures MCP in TOML — and Zed
names the block `context_servers`:

```json
{
  "mcpServers": {
    "graneth": {
      "command": "npx",
      "args": ["-y", "@graneth/mcp-server"]
    }
  }
}
```

| Client | Add it via | Config location |
| --- | --- | --- |
| **Claude Code** (CLI) | `claude mcp add --transport stdio graneth -- npx -y @graneth/mcp-server` | Writes to `~/.claude.json` (local scope, default). Add `--scope project` to write a shareable `.mcp.json` at the repo root instead. |
| **OpenAI Codex** (CLI) | `codex mcp add graneth -- npx -y @graneth/mcp-server` · verify with `codex mcp list` | `~/.codex/config.toml` — **TOML, not JSON**: `[mcp_servers.graneth]` with `command = "npx"` and `args = ["-y", "@graneth/mcp-server"]` |
| **Gemini CLI** | `gemini mcp add graneth npx -y @graneth/mcp-server` — or paste the snippet above | `~/.gemini/settings.json` (user) or `.gemini/settings.json` (this project only) |
| **Cursor** | Paste the snippet above | `~/.cursor/mcp.json` (global) or `<project-root>/.cursor/mcp.json` (this project only) |
| **VS Code** (GitHub Copilot, agent mode) | One-click "Add to VS Code" on [graneth.com](https://graneth.com) | VS Code's own MCP registry (Copilot reads it; Claude Code does not) |
| **Windsurf** | Paste the snippet above | `~/.codeium/windsurf/mcp_config.json` (macOS/Linux) · `%USERPROFILE%\.codeium\windsurf\mcp_config.json` (Windows) |
| **Zed** | Paste into settings — the block is `context_servers`, with `"source": "custom"` | `settings.json` (user) or `<project-root>/.zed/settings.json` |
| **Claude Desktop** | Paste the snippet above | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` · Windows: `%APPDATA%\Claude\claude_desktop_config.json` |
| **Any other MCP host** | Point it at `npx -y @graneth/mcp-server` | Nothing here is client-specific: the server speaks MCP over stdio and answers `initialize` + `tools/list` like any other. |

Then ask your agent to run `pre_flight_check` before suggesting a commit. A
`BLOCKED` verdict means: do not commit until the CRITICAL findings are fixed.

## Verdicts

| Verdict            | Meaning                                                    |
| ------------------ | ---------------------------------------------------------- |
| `CLEAR`            | No issues — safe to commit.                                |
| `REVIEW_REQUIRED`  | Warnings to confirm (new packages, lower-confidence).      |
| `BLOCKED`          | Critical issues (non-existent package / secret) — do not commit. |

## Second tool: `report_hallucination` (opt-in contribution)

When `pre_flight_check` catches a name that doesn't exist, you can donate it to
[Graneth's public threat feed](https://graneth.com/api/threat-feed) — one tool
call, **only after the human explicitly agrees** (the tool description
instructs the agent to ask first). What you get back: the name stays caught for
every user **even if an attacker registers the package later**, and the feed
entry can carry your public handle (`reporter`, optional).

Privacy is structural, not a promise:

- The call sends exactly **one package name + ecosystem** — never file contents.
  It is the only tool that talks to `graneth.com`, and only when invoked;
  `pre_flight_check` itself stays local + public registries.
- Only flat public namespaces are reportable (npm unscoped, PyPI, crates.io,
  RubyGems). Scoped npm names, Go module paths and composer `vendor/` pairs are
  rejected by the server — that's where company-internal names live, and a
  public feed must not leak them.
- The server re-verifies non-existence against the live registry before
  accepting, so the feed can't be poisoned with real packages.

## How it relates to Graneth

This server shares its detection core with the hosted
[Graneth](https://github.com/zubovartemiy/graneth-dashboard) scanner via the internal `@graneth/core-checks`
module, so local pre-flight results match what the full PR scan would find.

## Releasing (maintainers)

One command, from the repo root:

```bash
pnpm release:mcp            # every guard, then publish (asks for the 2FA OTP)
pnpm release:mcp --dry-run  # everything except the upload
```

`scripts/release-mcp.mjs` fails CLOSED on each step: root manifest must still
be `private:true`; the package must be exactly `@graneth/mcp-server`; branch
master + clean tree; the bundled threat-feed snapshot is refreshed (a changed
snapshot stops the release until its diff is reviewed and committed); and the
tarball file list is verified against a hard allowlist — one file outside
`dist/`, `README.md`, `LICENSE`, `package.json` aborts the publish. That last
guard is what makes "accidentally release the whole repository" structurally
impossible, not just unlikely.

## License

MIT
