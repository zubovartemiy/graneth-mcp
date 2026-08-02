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
 * Config snippet (e.g. Claude Code / Cursor mcp.json):
 *   {
 *     "mcpServers": {
 *       "graneth": { "command": "npx", "args": ["-y", "@graneth/mcp-server"] }
 *     }
 *   }
 */

import { createInterface } from "node:readline";
import { createServer, InvalidParams, ErrorCode, type Tool } from "./protocol.js";
// Bundled from source at build time (tsup) — no separate runtime dependency.
import { preFlightCheck, type FileInput } from "../../core-checks/src/index.js";
import type { CoreFinding } from "../../core-checks/src/types.js";

const VERSION = "0.7.1"; // zero-dependency transport (hand-rolled MCP core, no SDK/zod)

// ─── small inline validators (replacing zod; throw InvalidParams on bad input) ─

function requireObject(args: unknown): Record<string, unknown> {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new InvalidParams("arguments must be an object");
  }
  return args as Record<string, unknown>;
}

function requireString(v: unknown, field: string, min: number, max: number): string {
  if (typeof v !== "string") throw new InvalidParams(`\`${field}\` must be a string`);
  if (v.length < min) throw new InvalidParams(`\`${field}\` must be at least ${min} character(s)`);
  if (v.length > max) throw new InvalidParams(`\`${field}\` must be at most ${max} characters`);
  return v;
}

function optionalString(v: unknown, field: string, min: number, max: number): string | undefined {
  if (v === undefined || v === null) return undefined;
  return requireString(v, field, min, max);
}

// ─── pre_flight_check ──────────────────────────────────────────────────────────

const PRE_FLIGHT_CHECK_DESCRIPTION =
  "Security pre-flight check for local file changes BEFORE committing. Run this whenever you are about to suggest `git commit`, `git push`, or open a pull request — especially when changes add package imports or dependencies (package.json / requirements.txt / Cargo.toml / go.mod / Gemfile / composer.json / import statements) or could contain secrets. Detects AI-hallucinated (non-existent) packages by live-checking six registries (npm, PyPI, crates.io, RubyGems, Go module proxy, Packagist) plus a bundled public threat-feed snapshot, which keeps catching a known hallucinated name even after an attacker registers it; risk-scores dependencies an AI agent introduced by compounding metadata signals (new + install-scripts + low-adoption + no-provenance = an attack shape no single check flags); and finds hardcoded credentials via pattern + entropy analysis. Always free, no account required. Returns CLEAR, REVIEW_REQUIRED, or BLOCKED with specific findings and remediation.";

const PRE_FLIGHT_CHECK_INPUT_SCHEMA = {
  type: "object",
  properties: {
    files: {
      type: "array",
      minItems: 1,
      maxItems: 50,
      description: "Files staged for commit (path + content)",
      items: {
        type: "object",
        properties: {
          path: { type: "string", minLength: 1, maxLength: 1024, description: "Relative file path" },
          content: { type: "string", maxLength: 200_000, description: "Full file content to check" },
        },
        required: ["path", "content"],
        additionalProperties: false,
      },
    },
    context: { type: "string", maxLength: 500, description: "What these changes do (helps triage)" },
  },
  required: ["files"],
  additionalProperties: false,
} as const;

interface PreFlightInput {
  files: FileInput[];
  context?: string;
}

function parsePreFlight(args: unknown): PreFlightInput {
  const o = requireObject(args);
  if (!Array.isArray(o.files)) throw new InvalidParams("`files` must be an array");
  if (o.files.length < 1) throw new InvalidParams("`files` must contain at least 1 file");
  if (o.files.length > 50) throw new InvalidParams("`files` must contain at most 50 files");
  const files: FileInput[] = o.files.map((raw, i) => {
    if (!raw || typeof raw !== "object") throw new InvalidParams(`files[${i}] must be an object`);
    const f = raw as Record<string, unknown>;
    return {
      path: requireString(f.path, `files[${i}].path`, 1, 1024),
      content: requireString(f.content, `files[${i}].content`, 0, 200_000),
    };
  });
  return { files, context: optionalString(o.context, "context", 0, 500) };
}

const VERDICT_ACTION: Record<string, string> = {
  BLOCKED: "Do NOT commit these changes. Fix all CRITICAL findings before proceeding. Use each finding's `recommendation` for remediation.",
  REVIEW_REQUIRED: "Review warnings before committing. Each may be a false positive but should be manually confirmed.",
};
const DEFAULT_VERDICT_ACTION = "No security issues detected. Safe to commit.";

function verdictAction(verdict: string): string {
  return VERDICT_ACTION[verdict] ?? DEFAULT_VERDICT_ACTION;
}

function toPreFlightFinding(f: CoreFinding) {
  return {
    severity: f.severity,
    type: f.type,
    title: f.title,
    file: f.file,
    line: f.line,
    description: f.description,
    recommendation: f.recommendation,
    cve: f.cve,
  };
}

async function runPreFlightCheck(files: FileInput[], context: string | undefined) {
  const { verdict, findings, summary } = await preFlightCheck(files);
  return {
    verdict,
    summary: {
      filesChecked: summary.filesChecked,
      critical: summary.critical,
      warnings: summary.warnings,
      context: context ?? null,
    },
    findings: findings.slice(0, 20).map(toPreFlightFinding),
    action: verdictAction(verdict),
  };
}

const preFlightCheckTool: Tool<PreFlightInput> = {
  name: "pre_flight_check",
  description: PRE_FLIGHT_CHECK_DESCRIPTION,
  inputSchema: PRE_FLIGHT_CHECK_INPUT_SCHEMA,
  parse: parsePreFlight,
  async handler({ files, context }) {
    try {
      const result = await runPreFlightCheck(files, context);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Pre-flight check failed: ${String(err)}` }],
        isError: true,
      };
    }
  },
};

// ─── report_hallucination — the contribution half of the shared threat feed ───
//
// The ONLY tool that talks to graneth.com, and only when explicitly invoked:
// pre_flight_check stays fully local + public registries. The reward loop:
// a reported name enters the public feed, ships to every user in the next
// bundled snapshot, and stays caught even after an attacker registers the
// package — the moment a live existence check alone goes silent.
const REPORT_URL = "https://graneth.com/api/threat-feed/report";
const REPORTABLE_ECOSYSTEMS = ["npm", "pypi", "crates", "gems"] as const;
type ReportableEcosystem = (typeof REPORTABLE_ECOSYSTEMS)[number];

const REPORT_HALLUCINATION_DESCRIPTION =
  "Report an AI-hallucinated package name to Graneth's public threat feed, so every user's pre-flight catches it — permanently, even if an attacker registers the name later. IMPORTANT: only call this AFTER the human has explicitly agreed to report the name; ask them first. Sends exactly one package name + ecosystem to graneth.com (never file contents). The server re-verifies non-existence against the live registry before accepting. Reportable ecosystems: npm (unscoped), pypi, crates, gems — namespaced names (npm @scope, go, composer) are rejected to keep internal package names out of a public feed. Optional `reporter` is a public attribution handle shown on the feed entry.";

const REPORT_HALLUCINATION_INPUT_SCHEMA = {
  type: "object",
  properties: {
    package: { type: "string", minLength: 1, maxLength: 214, description: "The hallucinated package name (as caught by pre_flight_check)" },
    ecosystem: { type: "string", enum: [...REPORTABLE_ECOSYSTEMS], description: "Registry the name was checked against" },
    reporter: { type: "string", minLength: 2, maxLength: 30, description: "Optional public attribution handle ([a-zA-Z0-9_-])" },
  },
  required: ["package", "ecosystem"],
  additionalProperties: false,
} as const;

interface ReportInput {
  package: string;
  ecosystem: ReportableEcosystem;
  reporter?: string;
}

function parseReport(args: unknown): ReportInput {
  const o = requireObject(args);
  const eco = o.ecosystem;
  if (typeof eco !== "string" || !REPORTABLE_ECOSYSTEMS.includes(eco as ReportableEcosystem)) {
    throw new InvalidParams(`\`ecosystem\` must be one of: ${REPORTABLE_ECOSYSTEMS.join(", ")}`);
  }
  return {
    package: requireString(o.package, "package", 1, 214),
    ecosystem: eco as ReportableEcosystem,
    reporter: optionalString(o.reporter, "reporter", 2, 30),
  };
}

const REPORT_OUTCOME_TEXT: Record<string, (body: any) => string> = {
  accepted: (b) =>
    `Reported. "${b.entry?.name}" is in the public threat feed now (community tier)${b.entry?.reporter ? `, attributed to "${b.entry.reporter}"` : ""}. ` +
    `It stays caught for every Graneth user even if someone registers the name later. Feed: https://graneth.com/api/threat-feed`,
  duplicate: () => "Already in the threat feed — this name is covered for everyone. Nothing else to do.",
  rejected: (b) => `Not accepted: ${b.reason ?? "the report was rejected"}.`,
  unverifiable: (b) => `Could not verify right now: ${b.reason ?? "registry unreachable"}. Nothing was stored — try again shortly.`,
};

const reportHallucinationTool: Tool<ReportInput> = {
  name: "report_hallucination",
  description: REPORT_HALLUCINATION_DESCRIPTION,
  inputSchema: REPORT_HALLUCINATION_INPUT_SCHEMA,
  parse: parseReport,
  async handler({ package: pkg, ecosystem, reporter }) {
    try {
      const res = await fetch(REPORT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: pkg, ecosystem, reporter }),
        signal: AbortSignal.timeout(15_000),
      });
      const body = await res.json().catch(() => ({}));
      const render = REPORT_OUTCOME_TEXT[body.status as string];
      const text = render ? render(body) : `Unexpected response (HTTP ${res.status}) — nothing was stored.`;
      return { content: [{ type: "text", text }] };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Report failed before reaching the feed: ${String(err)}. Nothing was stored.` }],
        isError: true,
      };
    }
  },
};

// ─── stdio loop — newline-delimited JSON-RPC, one message per line ─────────────

async function main(): Promise<void> {
  const server = createServer({
    name: "graneth",
    version: VERSION,
    tools: [preFlightCheckTool, reportHallucinationTool],
  });

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  process.stderr.write(`[graneth-mcp-server] v${VERSION} ready on stdio (pre_flight_check, report_hallucination)\n`);

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let msg: unknown;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      // Unparseable line: no id to echo, emit the spec's ParseError with id null.
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: ErrorCode.ParseError, message: "Parse error" } }) + "\n");
      continue;
    }
    const response = await server.handleMessage(msg);
    if (response !== null) process.stdout.write(JSON.stringify(response) + "\n");
  }
}

main().catch((err) => {
  process.stderr.write(`[graneth-mcp-server] fatal: ${String(err)}\n`);
  process.exit(1);
});
