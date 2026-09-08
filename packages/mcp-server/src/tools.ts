/**
 * THE TWO TOOLS, SEPARATED FROM THE PROCESS THAT SERVES THEM.
 *
 * All of this lived in `index.ts` beside a top-level `main()` call, which made
 * it unreachable by any test: importing the module started the stdio loop and
 * blocked on stdin. So the validators, the formatters and the tool definitions
 * of a package that is PUBLISHED ON NPM and launched by other people's editors
 * were measured at 0% — not because nobody wrote the tests, but because nobody
 * could.
 *
 * `index.ts` keeps the shebang, the version and the wiring. Everything here is
 * a pure function or a plain object.
 */
import { InvalidParams, type Tool } from "./protocol.js";
import { preFlightCheck, type FileInput } from "../../core-checks/src/index.js";
import type { CoreFinding } from "../../core-checks/src/types.js";

// ─── small inline validators (replacing zod; throw InvalidParams on bad input) ─

export function requireObject(args: unknown): Record<string, unknown> {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new InvalidParams("arguments must be an object");
  }
  return args as Record<string, unknown>;
}

export function requireString(
  v: unknown,
  field: string,
  min: number,
  max: number
): string {
  if (typeof v !== "string")
    throw new InvalidParams(`\`${field}\` must be a string`);
  if (v.length < min)
    throw new InvalidParams(
      `\`${field}\` must be at least ${min} character(s)`
    );
  if (v.length > max)
    throw new InvalidParams(`\`${field}\` must be at most ${max} characters`);
  return v;
}

export function optionalString(
  v: unknown,
  field: string,
  min: number,
  max: number
): string | undefined {
  if (v === undefined || v === null) return undefined;
  return requireString(v, field, min, max);
}

// ─── pre_flight_check ──────────────────────────────────────────────────────────

export const MAX_FILES = 50;
export const MAX_PATH_CHARS = 1024;
export const MAX_CONTENT_CHARS = 200_000;
export const MAX_CONTEXT_CHARS = 500;
/** Findings beyond this are counted in the summary but not listed. */
export const MAX_LISTED_FINDINGS = 20;

const PRE_FLIGHT_CHECK_DESCRIPTION =
  "Security pre-flight check for local file changes BEFORE committing. Run this whenever you are about to suggest `git commit`, `git push`, or open a pull request — especially when changes add package imports or dependencies (package.json / requirements.txt / Cargo.toml / go.mod / Gemfile / composer.json / import statements) or could contain secrets. Detects AI-hallucinated (non-existent) packages by live-checking six registries (npm, PyPI, crates.io, RubyGems, Go module proxy, Packagist) plus a bundled public threat-feed snapshot, which keeps catching a known hallucinated name even after an attacker registers it; risk-scores dependencies an AI agent introduced by compounding metadata signals (new + install-scripts + deprecated + no-repository = an attack shape no single check flags); and finds hardcoded credentials via pattern + entropy analysis. Always free, no account required. Returns CLEAR, REVIEW_REQUIRED, or BLOCKED with specific findings and remediation.";

export const PRE_FLIGHT_CHECK_INPUT_SCHEMA = {
  type: "object",
  properties: {
    files: {
      type: "array",
      minItems: 1,
      maxItems: MAX_FILES,
      description: "Files staged for commit (path + content)",
      items: {
        type: "object",
        properties: {
          path: {
            type: "string",
            minLength: 1,
            maxLength: MAX_PATH_CHARS,
            description: "Relative file path",
          },
          content: {
            type: "string",
            maxLength: MAX_CONTENT_CHARS,
            description: "Full file content to check",
          },
        },
        required: ["path", "content"],
        additionalProperties: false,
      },
    },
    context: {
      type: "string",
      maxLength: MAX_CONTEXT_CHARS,
      description: "What these changes do (helps triage)",
    },
  },
  required: ["files"],
  additionalProperties: false,
} as const;

export interface PreFlightInput {
  files: FileInput[];
  context?: string;
}

export function parsePreFlight(args: unknown): PreFlightInput {
  const o = requireObject(args);
  if (!Array.isArray(o.files))
    throw new InvalidParams("`files` must be an array");
  if (o.files.length < 1)
    throw new InvalidParams("`files` must contain at least 1 file");
  if (o.files.length > MAX_FILES)
    throw new InvalidParams(
      `\`files\` must contain at most ${MAX_FILES} files`
    );
  const files: FileInput[] = o.files.map((raw, i) => {
    if (!raw || typeof raw !== "object")
      throw new InvalidParams(`files[${i}] must be an object`);
    const f = raw as Record<string, unknown>;
    return {
      path: requireString(f.path, `files[${i}].path`, 1, MAX_PATH_CHARS),
      content: requireString(
        f.content,
        `files[${i}].content`,
        0,
        MAX_CONTENT_CHARS
      ),
    };
  });
  return {
    files,
    context: optionalString(o.context, "context", 0, MAX_CONTEXT_CHARS),
  };
}

const VERDICT_ACTION: Record<string, string> = {
  BLOCKED:
    "Do NOT commit these changes. Fix all CRITICAL findings before proceeding. Use each finding's `recommendation` for remediation.",
  REVIEW_REQUIRED:
    "Review warnings before committing. Each may be a false positive but should be manually confirmed.",
};
const DEFAULT_VERDICT_ACTION = "No security issues detected. Safe to commit.";

export function verdictAction(verdict: string): string {
  return VERDICT_ACTION[verdict] ?? DEFAULT_VERDICT_ACTION;
}

export function toPreFlightFinding(f: CoreFinding) {
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

export async function runPreFlightCheck(
  files: FileInput[],
  context: string | undefined
) {
  const { verdict, findings, summary } = await preFlightCheck(files);
  return {
    verdict,
    summary: {
      filesChecked: summary.filesChecked,
      critical: summary.critical,
      warnings: summary.warnings,
      context: context ?? null,
    },
    // CRITICALS FIRST, THEN TRUNCATE.
    //
    // The listing is capped at 20 and the verdict is computed over ALL of them,
    // so a payload with 20 warnings ahead of one critical returned BLOCKED with
    // nothing critical listed — the file and line of the thing that blocked the
    // commit withheld from the only reader who could act on it. V8's sort is
    // stable, so within a severity the original order is untouched.
    findings: [...findings]
      .sort(
        (a, b) =>
          Number(b.severity === "critical") - Number(a.severity === "critical")
      )
      .slice(0, MAX_LISTED_FINDINGS)
      .map(toPreFlightFinding),
    action: verdictAction(verdict),
  };
}

export const preFlightCheckTool: Tool<PreFlightInput> = {
  name: "pre_flight_check",
  description: PRE_FLIGHT_CHECK_DESCRIPTION,
  inputSchema: PRE_FLIGHT_CHECK_INPUT_SCHEMA,
  parse: parsePreFlight,
  async handler({ files, context }) {
    try {
      const result = await runPreFlightCheck(files, context);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        content: [
          { type: "text", text: `Pre-flight check failed: ${String(err)}` },
        ],
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
export const REPORT_URL = "https://graneth.com/api/threat-feed/report";
export const REPORTABLE_ECOSYSTEMS = ["npm", "pypi", "crates", "gems"] as const;
export type ReportableEcosystem = (typeof REPORTABLE_ECOSYSTEMS)[number];

export const REPORT_TIMEOUT_MS = 15_000;
export const MAX_PACKAGE_CHARS = 214;

const REPORT_HALLUCINATION_DESCRIPTION =
  "Report an AI-hallucinated package name to Graneth's public threat feed, so every user's pre-flight catches it — permanently, even if an attacker registers the name later. IMPORTANT: only call this AFTER the human has explicitly agreed to report the name; ask them first. Sends exactly one package name + ecosystem to graneth.com (never file contents). The server re-verifies non-existence against the live registry before accepting. Reportable ecosystems: npm (unscoped), pypi, crates, gems — namespaced names (npm @scope, go, composer) are rejected to keep internal package names out of a public feed. Optional `reporter` is a public attribution handle shown on the feed entry.";

export const REPORT_HALLUCINATION_INPUT_SCHEMA = {
  type: "object",
  properties: {
    package: {
      type: "string",
      minLength: 1,
      maxLength: MAX_PACKAGE_CHARS,
      description:
        "The hallucinated package name (as caught by pre_flight_check)",
    },
    ecosystem: {
      type: "string",
      enum: [...REPORTABLE_ECOSYSTEMS],
      description: "Registry the name was checked against",
    },
    reporter: {
      type: "string",
      minLength: 2,
      maxLength: 30,
      description: "Optional public attribution handle ([a-zA-Z0-9_-])",
    },
  },
  required: ["package", "ecosystem"],
  additionalProperties: false,
} as const;

export interface ReportInput {
  package: string;
  ecosystem: ReportableEcosystem;
  reporter?: string;
}

export function parseReport(args: unknown): ReportInput {
  const o = requireObject(args);
  const eco = o.ecosystem;
  if (
    typeof eco !== "string" ||
    !REPORTABLE_ECOSYSTEMS.includes(eco as ReportableEcosystem)
  ) {
    throw new InvalidParams(
      `\`ecosystem\` must be one of: ${REPORTABLE_ECOSYSTEMS.join(", ")}`
    );
  }
  return {
    package: requireString(o.package, "package", 1, MAX_PACKAGE_CHARS),
    ecosystem: eco as ReportableEcosystem,
    reporter: optionalString(o.reporter, "reporter", 2, 30),
  };
}

const REPORT_OUTCOME_TEXT: Record<string, (body: any) => string> = {
  accepted: b =>
    `Reported. "${b.entry?.name}" is in the public threat feed now (community tier)${b.entry?.reporter ? `, attributed to "${b.entry.reporter}"` : ""}. ` +
    `It stays caught for every Graneth user even if someone registers the name later. Feed: https://graneth.com/api/threat-feed`,
  duplicate: () =>
    "Already in the threat feed — this name is covered for everyone. Nothing else to do.",
  rejected: b => `Not accepted: ${b.reason ?? "the report was rejected"}.`,
  unverifiable: b =>
    `Could not verify right now: ${b.reason ?? "registry unreachable"}. Nothing was stored — try again shortly.`,
};

/** What the caller is told about an outcome. Exported so it can be asserted. */
export function reportOutcomeText(body: any, httpStatus: number): string {
  const render = REPORT_OUTCOME_TEXT[body?.status as string];
  return render
    ? render(body)
    : `Unexpected response (HTTP ${httpStatus}) — nothing was stored.`;
}

export const reportHallucinationTool: Tool<ReportInput> = {
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
        signal: AbortSignal.timeout(REPORT_TIMEOUT_MS),
      });
      const body = (await res.json().catch(() => ({}))) as any;
      return {
        content: [{ type: "text", text: reportOutcomeText(body, res.status) }],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: `Report failed before reaching the feed: ${String(err)}. Nothing was stored.`,
          },
        ],
        isError: true,
      };
    }
  },
};

/** Everything this server exposes, in the order `tools/list` reports them. */
export const TOOLS = [preFlightCheckTool, reportHallucinationTool];
