# @graneth/mcp-server

An **account-free** [Model Context Protocol](https://modelcontextprotocol.io) server that
catches **AI-hallucinated dependencies** and **hardcoded secrets** before you commit —
straight inside your AI coding agent.

```bash
claude mcp add --transport stdio graneth -- npx -y @graneth/mcp-server
```

Any other MCP client — Cursor, Windsurf, Codex CLI, Zed, VS Code, Claude Desktop — takes the
same server through its own config; the per-client snippets are under
[Configure your agent](#configure-your-agent). No account, no API key, no credit card.

**Zero runtime dependencies** (verify: `npm view @graneth/mcp-server dependencies`). A
supply-chain security tool should be auditable in full — so the MCP/JSON-RPC layer is a small
hand-rolled core, not a framework, and `npm audit` on a fresh install is clean.

It exposes two tools over stdio: `pre_flight_check`, which is always free and never contacts
us, and the opt-in `report_hallucination`.

---

## `pre_flight_check`

Hand it files as `{ path, content }` — up to **50 files per call**, each up to **200,000
characters**. Larger calls are rejected with a JSON-RPC `InvalidParams` error rather than
silently truncated, and at most the first 20 findings come back.

The registry work is bounded too, and that is a separate budget from the input size: at most
**1,000 lookups** and **60 seconds** per call. Those limits exist because the input limits do
not imply them — 50 generated manifests can name far more dependencies than a check should
spend an unbounded afternoon on, from your address. Anything past the budget is reported as
`registry_unreachable`: a warning saying existence is UNKNOWN and the result is **not** a
verified-clean. It is never silently dropped, and never counted as clean.

The server does not read your git index. Your agent decides which files to send; the tool
checks whatever it is given. In practice that means the staged set, because the tool
description instructs the agent to run it just before proposing a commit.

### Detect hallucinated and slopsquatted packages

Package references are checked **live** against six registries — npm, PyPI, crates.io,
RubyGems, the Go module proxy, Packagist. A package the registry reports as absent is a strong
signal of an AI-invented dependency an attacker may have pre-registered. → **BLOCKED**

Where the references come from, precisely:

| Source                          | Ecosystems parsed                                                                       |
| ------------------------------- | --------------------------------------------------------------------------------------- |
| `import` / `require` statements | JavaScript, TypeScript, Python, Rust, Go                                                |
| Manifests                       | `package.json`, `requirements*.txt`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json` |

Ruby `require` and PHP `use` are deliberately **not** parsed from source — they name files and
namespaces, not packages — so Ruby and PHP coverage comes from `Gemfile` and `composer.json`
instead. Go imports from unrecognised vanity hosts are skipped in source and covered by
`go.mod`.

Only registry-resolvable dependencies are checked. Anything that does not name a registry
package is skipped without a finding: `workspace:`, `file:`, `link:`, `portal:`, `catalog:`,
git/GitHub and URL specifiers, `user/repo` shorthand, Cargo `path`/`git` deps, go modules with
a local `replace`, Gemfile `path:`/`git:`/`github:` gems, and composer platform requirements.
Only the six filenames above are read — `pyproject.toml`, `Pipfile`, `setup.py` and lockfiles
are not manifests to this tool.

"Absent" is not only a 404: the Go proxy may answer 410, and npm may answer 200 with an
unpublished tombstone. All three count as absent.

A manifest that fails to parse is reported rather than silently skipped — for the two JSON
manifests, `package.json` and `composer.json`. `Cargo.toml`, `go.mod`, `Gemfile` and
`requirements*.txt` are read line by line and have no parse-failure path: a malformed file of
those four kinds yields no dependencies and no finding. An unreachable registry is reported as
_could not verify_ — never as clean. → **REVIEW_REQUIRED**

### Catch known hallucinated names — even after an attacker registers them

A bundled snapshot of Graneth's public threat feed is checked locally, with no network call.
This is the case a live existence check cannot see: once a slopsquatter registers the name,
the package _exists_ — but the shared list keeps it **BLOCKED**. Community reports ship to
every user at the next release.

Each row carries its own provenance tier — `reported`, `pattern`, `observed` or `community` —
and every finding quotes the tier it came from, so a name caught by pattern inference is never
presented as a confirmed sighting.

### Flag brand-new packages

Published under 30 days ago — the band security guidance recommends flagging for manual review
(the Cloud Security Alliance suggests a 30–90 day window). → **REVIEW_REQUIRED**

Available on npm, PyPI, crates.io, RubyGems and Packagist. The Go module proxy does not expose
a first-publish date in one call, so Go modules are never flagged as new.

### Risk-score the dependencies your AI agent introduced

Existence is only the start. A _real_ package can still carry the shape attackers exploit —
brand-new, running an install script, deprecated, no linked source repository. No single
signal produces a warning; two already can. A brand-new package that **also** runs an install
script scores 52/100 and fires an advisory `dependency_risk_shape` warning.

This is explicitly a risk **assessment**, never a malware claim. → **REVIEW_REQUIRED**

Two limits worth stating, because the finding text lists only what added points:

- **npm only.** These signals come from the npm packument, so `dependency_risk_shape` cannot
  fire for PyPI, crates.io, RubyGems, Go or Packagist.
- A provenance attestation, when present, **lowers** the score. Its absence adds nothing and
  is never named in a finding. Download counts are not fetched at all, so adoption never
  contributes here either.

### Catch hardcoded secrets

Known credential patterns (AWS, GitHub, Slack, OpenAI `sk-…`/`sk-proj-…`, Anthropic
`sk-ant-…`, Stripe `sk_live_…`, PEM private keys) plus Shannon-entropy analysis with semantic
variable-name context. → **BLOCKED** / **REVIEW_REQUIRED**

Vendor-documented sample keys and secrets in test or fixture files are downgraded to warnings —
surfaced, but they will not block a commit.

### What leaves your machine

Nothing but package names. `pre_flight_check` runs locally; its only network calls are to the
six public registries, and each sends the package name alone. The one exception is crates.io,
which rejects anonymous requests, so lookups there carry a fixed User-Agent identifying the
tool — `graneth-core-checks (+https://graneth.com)`. It identifies the tool, never you, your
repository or your files.

**Package names include your private ones, unless the payload proves otherwise.** A name is a
name: if your code imports `@acme/billing-core` and that package lives in a private registry,
the check asks npmjs.org about `@acme/billing-core`, because there is no way to tell a private
package from an invented one without asking. Two things narrow this and neither closes it:

- When the files you pass carry the EVIDENCE that a name is internal — a `tsconfig.json`
  `paths` alias, the manifest's own `name`, a `workspace:` dependency — the name is not looked
  up at all and not reported. Include your `tsconfig.json` and root `package.json` in the
  payload and your workspace packages stay local.
- Nothing else is sent: not the file, not the line, not the version range, not the repository.
  The name travels in the URL path, so it is visible to the registry and to anything between
  you and it.

If an internal name must never leave the machine even as a name, do not pass the files that
mention it. A `GOPRIVATE`-style prefix convention is not evidence this tool can see, and a
private name with no evidence in the payload is looked up and — when the public registry 404s
— reported as a probable hallucination.

---

## Verdicts

| Verdict           | Meaning                                                           |
| ----------------- | ----------------------------------------------------------------- |
| `CLEAR`           | No issues — safe to commit.                                       |
| `REVIEW_REQUIRED` | Warnings to confirm (new packages, risk shape, lower-confidence). |
| `BLOCKED`         | Critical — do not commit until fixed.                             |

`BLOCKED` covers three cases, not two: a package that does not exist, a hardcoded secret, and
a name on the bundled threat-feed snapshot — **including one an attacker has since
registered**, which is the whole point of shipping the list.

---

## Install / run

```bash
npx -y @graneth/mcp-server
```

Requires Node ≥ 18.

## Configure your agent

Most clients take this exact JSON block; only the file it goes in (or the CLI command)
differs. Codex configures MCP in TOML, Zed names the block `context_servers`, and VS Code uses
a `servers` root key:

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

| Client                           | Add it via                                                                           | Config location                                                                                                                                                                      |
| -------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Claude Code** (CLI)            | `claude mcp add --transport stdio graneth -- npx -y @graneth/mcp-server`             | Writes to `~/.claude.json` (local scope). Add `--scope project` for a shareable `.mcp.json` at the repo root.                                                                        |
| **OpenAI Codex** (CLI)           | `codex mcp add graneth -- npx -y @graneth/mcp-server` · verify with `codex mcp list` | `~/.codex/config.toml` — **TOML, not JSON**: `[mcp_servers.graneth]` with `command = "npx"` and `args = ["-y", "@graneth/mcp-server"]`                                               |
| **Gemini CLI**                   | `gemini mcp add graneth npx -y @graneth/mcp-server` — or paste the snippet           | `~/.gemini/settings.json` (user) or `.gemini/settings.json` (project)                                                                                                                |
| **Cursor**                       | Paste the snippet                                                                    | `~/.cursor/mcp.json` (global) or `<project-root>/.cursor/mcp.json` (project)                                                                                                         |
| **VS Code** (Copilot agent mode) | Paste the snippet, renaming the root key to `servers`                                | `.vscode/mcp.json` in the workspace, or the user-level `mcp.json` via **MCP: Open User Configuration**                                                                               |
| **Windsurf**                     | Paste the snippet                                                                    | `~/.codeium/windsurf/mcp_config.json` · Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`                                                                                   |
| **Zed**                          | Paste into settings — the block is `context_servers`                                 | `~/.config/zed/settings.json` (Linux) · `~/Library/Application Support/Zed/settings.json` (macOS) · `%APPDATA%\Zed\settings.json` (Windows) · or `<project-root>/.zed/settings.json` |
| **Claude Desktop**               | Paste the snippet                                                                    | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` · Windows: `%APPDATA%\Claude\claude_desktop_config.json`                                                    |
| **Any other MCP host**           | Point it at `npx -y @graneth/mcp-server`                                             | Nothing here is client-specific: the server speaks MCP over stdio and answers `initialize` + `tools/list` like any other.                                                            |

Older Zed builds required `"source": "custom"` inside each entry; the current Zed
documentation omits it. Add it only if your version rejects the block without it.

Then ask your agent to run `pre_flight_check` before suggesting a commit. A `BLOCKED` verdict
means: do not commit until the CRITICAL findings are fixed.

---

## `report_hallucination` — opt-in contribution

When `pre_flight_check` catches a name that doesn't exist, you can donate it to
[Graneth's public threat feed](https://graneth.com/api/threat-feed). What you get back: the
name stays caught for every user **even if an attacker registers the package later**.

Be clear about what the consent step is and is not. The tool description instructs the agent
to ask you before calling it — that is an instruction to the model, not a gate in the server.
Nothing in the code can verify that you agreed. If you want a hard guarantee, do not install
the tool with autonomous tool-calling enabled.

Of the three privacy properties below, **one is structural and two are the server's policy** —
a distinction worth keeping straight:

- **Structural.** The request body is constructed as exactly `{ package, ecosystem, reporter }`,
  so file contents cannot leave your machine no matter what the server does. This is also the
  only tool that talks to `graneth.com`; `pre_flight_check` stays local + public registries.
- **Server policy.** Only flat public namespaces are accepted (npm unscoped, PyPI, crates.io,
  RubyGems). Scoped npm names, Go module paths and composer `vendor/` pairs are rejected —
  that is where company-internal names live, and a public feed must not leak them. Note the
  rejection happens _after_ the name arrives: this package does not filter the name shape
  before sending, so a scoped internal name you report is refused by the server rather than
  withheld by the client.
- **Server policy.** Non-existence is re-verified against the live registry before accepting,
  so a package that already exists cannot be reported. Acceptance is a point-in-time proof: a
  name accepted while absent stays on the feed if someone registers it afterwards. That is the
  intended catch — and it means the check is on the name's state at report time, not forever.

---

## How it relates to Graneth

This server shares its detection core with the hosted [Graneth](https://graneth.com) scanner
through the `@graneth/core-checks` module, so the checks that run locally are the same code
the hosted scanner runs.

They do not produce matching results, and it would be misleading to imply so. What ships here
is existence, package age, the bundled snapshot, risk shape and secrets — the portable core.
The full PR scan then adds typosquat/edit-distance detection, a Postgres-cached package
verifier, Semgrep rules, reachability and taint analysis, cross-file stitching and LLM triage,
none of which exist in this package. A clean pre-flight is not a prediction of a clean scan.

`@graneth/core-checks` is an internal workspace package bundled into this package's `dist/`.
It is **not** on npm and cannot be installed separately; its source is mirrored alongside this
package at [zubovartemiy/graneth-mcp](https://github.com/zubovartemiy/graneth-mcp). Every
detection module is mirrored there in source — the only files held back are the tests whose
fixtures are literal example credentials.

## How this package is released

The release script lives in the private monorepo, not in this tree — but what it refuses to do
is worth stating, because it is the reason a supply-chain tool can be trusted with its own
supply chain. Every step fails **closed**:

1. the monorepo's root manifest must still be `private: true` — the structural npm block;
2. the package being released must be exactly `@graneth/mcp-server`, and not private;
3. branch `master`, clean working tree — no half-made state can ship;
4. npm authentication is checked before any work, so an expired token aborts early instead of
   surfacing later as npm's misleading 404;
5. the bundled threat-feed snapshot is refreshed first — a changed snapshot stops the release
   until its diff is reviewed and committed;
6. the tarball's file list is checked against a hard allowlist — one file outside `dist/`,
   `README.md`, `LICENSE`, `package.json` aborts the publish.

What makes "accidentally publish the whole repository" _structurally_ impossible is not step 6
but the manifest itself: `"files": ["dist", "README.md", "LICENSE"]` bounds the tarball however
publish is invoked, and the monorepo root is `private: true`. Step 6 is the check that proves
that held before anything is uploaded — it runs when you use the release script, which is the
sanctioned path. This project has the incident that taught it both.

## License

MIT — see [LICENSE](LICENSE).
