#!/usr/bin/env node
/**
 * @graneth/mcp-server — standalone, account-free Model Context Protocol server.
 *
 * Exposes the FREE `pre_flight_check` tool over stdio so AI coding agents
 * (Claude Code, Cursor, …) can catch AI-hallucinated dependencies and hardcoded
 * secrets in locally-staged changes BEFORE `git commit` / `git push`.
 *
 * No Graneth account, API key, or hosted backend is required: the checks run
 * locally and hit the public registries directly (npm, PyPI, crates.io,
 * RubyGems, the Go module proxy, Packagist). This is the same detection core
 * the Graneth server uses (shared via @graneth/core-checks), so results
 * don't drift.
 *
 * ZERO runtime dependencies: the JSON-RPC/MCP layer is a small hand-rolled core
 * (protocol.ts) instead of @modelcontextprotocol/sdk, and validation is done
 * inline instead of with zod. core-checks is bundled from source at build time.
 * A supply-chain security tool you can audit in full — `npm view` shows no deps.
 *
 * ── WHAT IS IN THIS FILE, AND WHY IT IS SO LITTLE ───────────────────────────
 * The tools, the validators and the loop used to live here, under a top-level
 * `main()` call. That combination made all of them untestable: importing the
 * module started the server and blocked on stdin, so the entry point of a
 * package that other people install and run measured 0% covered — not for want
 * of tests, but because no test could reach it. They are now `tools.ts` and
 * `stdio.ts`, and this file is the wiring, which is the one part a test cannot
 * meaningfully assert anyway.
 *
 * Config snippet (e.g. Claude Code / Cursor mcp.json):
 *   {
 *     "mcpServers": {
 *       "graneth": { "command": "npx", "args": ["-y", "@graneth/mcp-server"] }
 *     }
 *   }
 */

import { createServer } from "./protocol.js";
import { TOOLS } from "./tools.js";
import { serveStdio } from "./stdio.js";

const VERSION = "0.7.2"; // zero-dependency transport (hand-rolled MCP core, no SDK/zod)

async function main(): Promise<void> {
  const server = createServer({
    name: "graneth",
    version: VERSION,
    tools: TOOLS,
  });

  // stderr, not stdout: stdout carries the protocol and a stray line on it is
  // a parse error at the other end.
  process.stderr.write(
    `[graneth-mcp-server] v${VERSION} ready on stdio (${TOOLS.map(t => t.name).join(", ")})\n`
  );

  await serveStdio({
    server,
    input: process.stdin,
    output: process.stdout,
  });
}

main().catch(err => {
  process.stderr.write(`[graneth-mcp-server] fatal: ${String(err)}\n`);
  process.exit(1);
});
