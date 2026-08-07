/**
 * pre_flight_check core — account-free, framework-free security gate.
 *
 * Combines:
 *   1. Hallucinated-package detection (does each imported package exist?)
 *   2. Hardcoded-secret detection (known credential patterns + Shannon entropy)
 *
 * Returns a verdict (BLOCKED / REVIEW_REQUIRED / CLEAR) plus findings. Runs
 * entirely locally except for the registry existence lookups against npm/PyPI —
 * no Graneth account, API key, or hosted backend required.
 */

import type { CoreFinding } from "./types.js";
import { extractImportedPackages, type FileInput, type PackageRef } from "./imports.js";
import { extractManifestPackages } from "./manifests.js";
import { extractInternalNameEvidence, isInternalName } from "./internalNames.js";
import { computeDependencyRisk, isStackedRisk } from "./riskScore.js";
import { packageExists, type RegistryResult } from "./registry.js";
import { knownHallucination } from "./knownHallucinations.js";
import {
  KNOWN_SECRET_PATTERNS,
  EXAMPLE_CREDENTIALS,
  extractSecretCandidates,
  shannonEntropy,
  detectCharset,
  computeConfidence,
  SEMANTIC_SECRET_KEYWORDS,
  MIN_SECRET_LENGTH,
  MAX_SECRET_LENGTH,
} from "./secrets.js";

export type Verdict = "BLOCKED" | "REVIEW_REQUIRED" | "CLEAR";

export interface PreFlightResult {
  verdict: Verdict;
  findings: CoreFinding[];
  summary: { filesChecked: number; critical: number; warnings: number };
}

// ─── Secret scan (mirrors advancedAnalyzer.analyzePatchContent secret loop) ────

/**
 * Test/fixture locations where real-shaped secrets are usually deliberate
 * fakes. Findings there are downgraded to warnings (REVIEW_REQUIRED), never
 * dropped — a real key pasted into a test is still a leak worth surfacing.
 */
export const TEST_FIXTURE_PATH_RE =
  /(^|[\\/])(__tests__|__mocks__|fixtures?|testdata|tests?)[\\/]|\.(test|spec)\.[^\\/]+$|(^|[\\/])test_[^\\/]*\.py$|_test\.py$|(^|[\\/])conftest\.py$/i;

/**
 * GENERATED OR VENDORED ARTIFACTS — code a machine emitted or a third party
 * wrote, checked into the repository.
 *
 * WARNING: THIS EXISTS BECAUSE A CRITICAL HERE AUTO-REJECTS A LEGITIMATE PULL
 * REQUEST, measured by `pnpm health:precision-sweep` on 2026-08-06: over 26
 * upstream repositories and 73 PRs it produced exactly two false-positive
 * criticals, both in `vercel/next.js` →
 * `packages/next/src/compiled/sass-loader/cjs.js:2` — an `eval()` and a
 * "user input flows to a file system sink" inside a vendored, minified bundle.
 * Nobody wrote that line in that PR; a bundler emitted it.
 *
 * Same treatment as the test-fixture class above: findings are **downgraded to
 * warnings, never dropped**. A secret genuinely committed into `dist/` is still
 * a leak worth surfacing, and going quiet would trade a false positive for a
 * false negative — the wrong direction for this product, whose contract is that
 * a check unable to speak confidently says so.
 *
 * Every entry must be a PATH SEGMENT (or a filename suffix). `compiled` and
 * `dist` as bare substrings would swallow `compiledTemplates.ts` and
 * `distance.ts`, which are ordinary source, and that hole is exactly the
 * false-negative direction this comment just refused.
 */
export const GENERATED_ARTIFACT_PATH_RE =
  /(^|[\\/])(compiled|dist|build|vendor|vendored|third_party|node_modules)[\\/]|\.min\.(js|css)$|\.bundle\.js$/i;

/** Known secret patterns on one line (no entropy required — high-precision regexes). */
function knownPatternFindingsForLine(content: string, path: string, lineNo: number): CoreFinding[] {
  const findings: CoreFinding[] = [];
  for (const { pattern, title, description, cve } of KNOWN_SECRET_PATTERNS) {
    const match = content.match(pattern);
    if (!match) continue;
    // Vendor-documented sample keys (AWS docs etc.) are real-shaped but grant
    // nothing — downgrade so a docs snippet can't block a commit, but keep it
    // visible in case a real key was pasted next to the placeholder.
    const isExample = EXAMPLE_CREDENTIALS.has(match[0]);
    findings.push({
      type: "hardcoded_secret",
      severity: isExample ? "warning" : "critical",
      title: isExample ? `${title} (documented example value)` : title,
      description: isExample
        ? `${description} Found in \`${path}\`. The matched value is published verbatim in vendor documentation — almost certainly a placeholder.`
        : `${description} Found in \`${path}\`.`,
      file: path,
      line: lineNo,
      recommendation: isExample
        ? "Confirm this is the documented placeholder and not a real credential; prefer an obviously fake value."
        : "Rotate this credential immediately. Store secrets in environment variables or a secrets manager.",
      cve,
    });
  }
  return findings;
}

/** First qualifying Shannon-entropy candidate on one line (max one finding per line). */
function entropyFindingForLine(content: string, path: string, lineNo: number): CoreFinding | null {
  for (const { value, varName } of extractSecretCandidates(content)) {
    if (value.length < MIN_SECRET_LENGTH || value.length > MAX_SECRET_LENGTH) continue;

    const h = shannonEntropy(value);
    const cs = detectCharset(value);
    const { charset, threshold } = cs;
    if (h < threshold) continue;

    const confidence = computeConfidence(h, cs, varName);
    const confidencePct = Math.round(confidence * 100);
    const hasSemanticContext = !!varName && SEMANTIC_SECRET_KEYWORDS.some((kw) => varName.includes(kw));
    if (confidence < 0.55 && !hasSemanticContext) continue;

    const charsetLabel = charset === "hex" ? "hex" : charset === "base64" ? "base64/alphanumeric" : "high-entropy";
    const contextNote = hasSemanticContext
      ? ` Variable name \`${varName}\` matches secret keyword pattern → confidence ${confidencePct}%.`
      : ` No semantic variable name context → confidence ${confidencePct}%.`;

    return {
      type: "high_entropy_secret",
      severity: confidence >= 0.8 ? "critical" : "warning",
      title: `High-entropy ${charsetLabel} string — possible hardcoded secret`,
      description: `Entropy ${h.toFixed(2)} bits/char (${charset} threshold: ${threshold}) on line ${lineNo} of \`${path}\`.${contextNote}`,
      file: path,
      line: lineNo,
      recommendation: "Move this value to an environment variable or secrets manager and regenerate it if it was ever committed.",
      cve: "CWE-798",
    };
  }
  return null;
}

/** In a test/fixture file, a critical secret finding becomes a warning with the reason attached. */
function downgradeForTestPath(f: CoreFinding): CoreFinding {
  if (f.severity !== "critical") return f;
  return {
    ...f,
    severity: "warning",
    description: `${f.description} Located in a test/fixture file — usually a deliberate fake; confirm it is not a real credential.`,
  };
}

function scanSecrets(files: FileInput[]): CoreFinding[] {
  const findings: CoreFinding[] = [];

  for (const file of files) {
    const isTestPath = TEST_FIXTURE_PATH_RE.test(file.path);
    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const content = lines[i];
      const lineNo = i + 1;
      const trimmed = content.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

      let lineFindings = knownPatternFindingsForLine(content, file.path, lineNo);
      const entropyFinding = entropyFindingForLine(content, file.path, lineNo);
      if (entropyFinding) lineFindings = [...lineFindings, entropyFinding];
      findings.push(...(isTestPath ? lineFindings.map(downgradeForTestPath) : lineFindings));
    }
  }
  return findings;
}

// ─── Package existence scan ────────────────────────────────────────────────────

/** Human-readable registry name + site per ecosystem (six registries). */
const REGISTRY_LABEL: Record<string, { name: string; site: string }> = {
  npm:      { name: "npm",       site: "npmjs.com" },
  pypi:     { name: "PyPI",      site: "pypi.org" },
  crates:   { name: "crates.io", site: "crates.io" },
  gems:     { name: "RubyGems",  site: "rubygems.org" },
  go:       { name: "the Go module proxy", site: "pkg.go.dev" },
  composer: { name: "Packagist", site: "packagist.org" },
};

function registryLabel(eco: string): { name: string; site: string } {
  return REGISTRY_LABEL[eco] ?? { name: eco, site: eco };
}

/** Honest fail-open marker: existence is UNKNOWN, so the result must say so —
 *  a warning (REVIEW_REQUIRED), never a commit-blocking critical, and never a
 *  silent CLEAR (the fail-safe contract). */
function unreachableFinding(pkg: string, eco: string, file: string, line: number): CoreFinding {
  const { name, site } = registryLabel(eco);
  return {
    type: "registry_unreachable",
    severity: "warning",
    title: `Could not verify "${pkg}" — ${name} was unreachable`,
    description:
      `${name} could not be reached during this check, so it is UNKNOWN whether "${pkg}" is a real package ` +
      `or an AI-hallucinated (slopsquatted) name. This result is NOT a verified-clean.`,
    file,
    line,
    recommendation: `Re-run the check when the network is available, or verify "${pkg}" manually on ${site}.`,
    cve: "CWE-1357",
  };
}

async function scanPackages(files: FileInput[]): Promise<CoreFinding[]> {
  // Issue #152: tsconfig path aliases and workspace packages are valid-looking
  // names that 404 by design. When the payload itself carries the evidence
  // (tsconfig paths / workspace manifests), such imports are internal — not
  // hallucinations. No evidence → detection stays on.
  const evidence = extractInternalNameEvidence(files);
  const refs = extractImportedPackages(files).filter(
    (r) => !(r.ecosystem === "npm" && isInternalName(r.pkg, evidence)),
  );

  // Manifest-declared dependencies (package.json / requirements.txt) — the
  // most common way AI agents add packages; import statements alone miss them.
  const manifest = extractManifestPackages(files);
  const seen = new Set(refs.map((r) => `${r.pkg}::${r.ecosystem}`));
  for (const ref of manifest.refs) {
    const key = `${ref.pkg}::${ref.ecosystem}`;
    if (!seen.has(key)) {
      seen.add(key);
      refs.push(ref);
    }
  }

  // Fail-safe: an unreadable manifest must surface as a finding, never as a
  // silent "clean" (its dependencies were NOT verified).
  const findings: CoreFinding[] = manifest.errors.map((e) => ({
    type: "manifest_unparsable",
    severity: "warning" as const,
    title: `Could not parse ${e.file} — its dependencies were NOT verified`,
    description: `\`${e.file}\` could not be parsed (${e.message}), so its dependencies were not checked against the registry. This diff is not known-clean.`,
    file: e.file,
    line: 1,
    recommendation: "Fix the manifest syntax and re-run the check before committing.",
  }));

  if (refs.length === 0) return findings;

  const CONCURRENCY = 8;

  for (let i = 0; i < refs.length; i += CONCURRENCY) {
    const batch = refs.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async (ref) => ({ ref, signal: await packageExists(ref.pkg, ref.ecosystem) })),
    );

    for (let j = 0; j < results.length; j++) {
      const r = results[j];
      if (r.status !== "fulfilled") {
        // A crashed lookup is UNKNOWN, not clean — surface it (fail-safe).
        const ref = batch[j];
        findings.push(unreachableFinding(ref.pkg, ref.ecosystem, ref.filename, ref.line));
        continue;
      }
      const { ref, signal } = r.value;
      const registryName = registryLabel(ref.ecosystem).name;

      // Shared threat-feed snapshot beats every registry branch: a listed name
      // is a known hallucination whether it 404s, was registered since (the
      // window a live existence check cannot see), or the registry is down —
      // the list is local. One authoritative finding; the weaker branches are
      // skipped so the same name never double-reports.
      const knownFinding = knownHallucinationFinding(ref, signal, registryName);
      if (knownFinding) {
        findings.push(knownFinding);
        continue;
      }

      if (signal.unreachable) {
        findings.push(unreachableFinding(ref.pkg, ref.ecosystem, ref.filename, ref.line));
      } else if (!signal.exists) {
        findings.push({
          type: "ghost_package",
          severity: "critical",
          title: `Package "${ref.pkg}" does not exist in ${registryName}`,
          description:
            `"${ref.pkg}" is not a real package — verified live against ${registryName} (404). ` +
            `This is the hallmark of an AI-hallucinated dependency (slopsquatting): the model invented a plausible name, ` +
            `and an attacker may have already pre-registered it with malicious code. Found in \`${ref.filename}\` at line ${ref.line}.`,
          file: ref.filename,
          line: ref.line,
          recommendation:
            `Remove the reference to "${ref.pkg}" immediately. Do not install it — ` +
            `if the name has been registered since, you may pull malicious code. Find the intended package on ` +
            `${registryLabel(ref.ecosystem).site} and replace the reference. ` +
            `If the human agrees, report the name with the report_hallucination tool — it enters the public ` +
            `threat feed and stays caught for everyone, even if an attacker registers it later.`,
          cve: "CWE-1357",
        });
      } else if (signal.isNewPackage) {
        const age = signal.publishedAt
          ? Math.floor((Date.now() - signal.publishedAt.getTime()) / (24 * 60 * 60 * 1000))
          : null;
        const ageStr = age !== null ? `${age} day${age !== 1 ? "s" : ""} ago` : "recently";
        findings.push({
          type: "new_package_risk",
          severity: "warning",
          title: `"${ref.pkg}" was published ${ageStr} — high-risk window`,
          description:
            `"${ref.pkg}" is a real ${ref.ecosystem} package but was first published ${ageStr}. ` +
            `Attackers pre-register hallucinated package names and wait for AI-generated code to install them.`,
          file: ref.filename,
          line: ref.line,
          recommendation: `Verify the publisher is trustworthy and the package is the one you intended before installing.`,
          cve: "CWE-1357",
        });
      }

      // Composite risk shape (the stack-catch), additive for EXISTING packages.
      const riskFinding = dependencyRiskShapeFinding(ref, signal);
      if (riskFinding) findings.push(riskFinding);
    }
  }
  return findings;
}

/**
 * One finding for a name on the bundled threat-feed snapshot, or null when the
 * name is unlisted. THREE states, because two were not enough.
 *
 * ── THE DEFECT THIS REPLACES ────────────────────────────────────────────────
 * `registeredSince` used to be `!signal.unreachable && signal.exists` — "the
 * package exists today" — and from that alone this function told the user the
 * package "was registered AFTER the name was catalogued", that this is "the
 * slopsquatting end-game: an attacker registering a name AI models keep
 * inventing", at CRITICAL, with "treat the registered package as hostile".
 *
 * Existing today does not mean registered since. Measured against npm and PyPI
 * on 2026-08-04, of the 35 names in this snapshot 19 are absent and **all 16
 * that exist were first published BEFORE the date we recorded the name** —
 * `react-gpt` in 2015, `express-ai` in 2016, `django-ai` in 2017. Not one was
 * taken by a squatter afterwards. So every firing of the "registered since"
 * branch was a hostility claim about somebody's real package, shipped in a free
 * tool that anyone can run, naming projects with identifiable authors.
 *
 * The snapshot now carries `recorded`, so the comparison the sentence always
 * implied can actually be made:
 *
 *   exists AND first published AFTER recorded  → the squat. Critical, and the
 *                                                one case the wording was
 *                                                written for.
 *   exists AND published at/before recorded    → a REAL package that models
 *   (or the date is unknown)                     also invent. Worth saying —
 *                                                the model may have meant
 *                                                something else — but there is
 *                                                nothing hostile here and we do
 *                                                not imply there is.
 *   absent                                     → the classic ghost. Critical.
 *
 * The unknown-date case sits with the harmless one deliberately. That is not
 * the fail-safe contract weakened: fail-safe forbids reporting a check that
 * could not run as CLEAN, and the existence check still runs and still reports.
 * What an unknown date may not do is support an accusation against a third
 * party.
 */
/**
 * How the row got onto the list, in words the tier can actually support.
 *
 * The tier is quoted straight into the finding, so it is a public sentence
 * rather than an internal label. `pattern` rows are Graneth's own
 * constructions: the name may well be one a model produces — that is the
 * premise of the pattern — but nobody has reported it, and saying "a name AI
 * models are known to invent" about a name we wrote ourselves is the claim this
 * clause exists to prevent.
 */
function provenanceClause(tier: string): string {
  switch (tier) {
    case "reported":
      return "a name outside research reports generative assistants suggest — see https://graneth.com/api/threat-feed for the source and its link";
    case "observed":
      return "a name Graneth has seen an assistant produce";
    case "community":
      return "a name a user reported, verified absent from the registry at report time";
    default:
      return 'a name Graneth built from the documented "popular library + generic AI suffix" pattern — our own construction, not a name anyone has reported';
  }
}

function knownHallucinationFinding(ref: PackageRef, signal: RegistryResult, registryName: string): CoreFinding | null {
  const known = knownHallucination(ref.pkg, ref.ecosystem);
  if (!known) return null;

  const exists = !signal.unreachable && signal.exists;
  const firstPublished = signal.publishedAt ? signal.publishedAt.toISOString().slice(0, 10) : null;
  const registeredSince = exists && !!known.recorded && !!firstPublished && firstPublished > known.recorded;

  if (registeredSince) {
    return {
      type: "known_hallucination",
      severity: "critical",
      title: `"${ref.pkg}" is a known hallucinated name — and has SINCE BEEN REGISTERED`,
      description: `"${ref.pkg}" is in Graneth's public threat feed (${known.tier} tier) — ${provenanceClause(known.tier)} — recorded ${known.recorded}, and the ${registryName} package now under it was registered afterwards, first published ${firstPublished}. That is the slopsquatting end-game: somebody registered the name after it was catalogued as one an assistant produces. An existence check alone would stay silent here. Found in \`${ref.filename}\` at line ${ref.line}.`,
      file: ref.filename,
      line: ref.line,
      recommendation: `Do NOT install "${ref.pkg}" under any circumstances — treat the registered package as hostile until proven otherwise. Find the package you actually intended and replace the reference.`,
      cve: "CWE-1357",
    };
  }

  if (exists) {
    return {
      type: "known_hallucination",
      severity: "warning",
      title: `"${ref.pkg}" is on Graneth's hallucinated-name list — and a real ${registryName} package by that name exists`,
      description: `"${ref.pkg}" is in Graneth's public threat feed (${known.tier} tier): ${provenanceClause(known.tier)}. A real ${registryName} package exists under it${firstPublished ? `, first published ${firstPublished}` : ""}${known.recorded && firstPublished ? ` — before we recorded the name (${known.recorded}), so this is not a squat and nothing here is a judgement on that package or its author` : " — we could not establish when it was first published, so we make no claim about it"}. Check that it is the package you actually meant, not one your assistant reached for because the name sounded right. Found in \`${ref.filename}\` at line ${ref.line}.`,
      file: ref.filename,
      line: ref.line,
      recommendation: `Confirm "${ref.pkg}" is the library you intended before installing it. The full feed: https://graneth.com/api/threat-feed`,
      cve: "CWE-1357",
    };
  }

  return {
    type: "known_hallucination",
    severity: "critical",
    title: `"${ref.pkg}" is on Graneth's hallucinated-name list and does not exist`,
    description: `"${ref.pkg}" is in Graneth's public threat feed (${known.tier} tier): ${provenanceClause(known.tier)}. It does not exist on ${registryName} today, but hallucinated names get pre-registered by attackers. Found in \`${ref.filename}\` at line ${ref.line}.`,
    file: ref.filename,
    line: ref.line,
    recommendation: `Remove the reference to "${ref.pkg}" and use the package you actually intended. The full feed: https://graneth.com/api/threat-feed`,
    cve: "CWE-1357",
  };
}

/**
 * The compounded, advisory risk shape (issue: the AI-introduced-dependency
 * score). Several individually-weak signals compounding into an attack shape
 * that no single check flags — a low-adoption malicious package or a patient
 * squat. NOT a malware verdict. Returns null unless the shape is genuinely
 * stacked (single dominant signals already have their own findings). The MCP
 * payload carries the npm trust signals parsed from the same packument, so
 * this needs no extra fetch.
 */
function dependencyRiskShapeFinding(ref: PackageRef, signal: RegistryResult): CoreFinding | null {
  if (!signal.exists || signal.unreachable) return null;
  const risk = computeDependencyRisk({
    exists: true,
    isNewPackage: signal.isNewPackage,
    ageDays: signal.publishedAt ? Math.floor((Date.now() - signal.publishedAt.getTime()) / 86_400_000) : null,
    hasRepository: signal.hasRepository,
    hasProvenance: signal.hasProvenance,
    hasInstallScripts: signal.hasInstallScripts,
    isDeprecated: signal.isDeprecated,
  });
  if (!isStackedRisk(risk)) return null;
  const shape = risk!.factors.filter((f) => f.points > 0).map((f) => f.note).join(" ");
  return {
    type: "dependency_risk_shape",
    severity: "warning",
    title: `"${ref.pkg}" has a compounded supply-chain risk shape (${risk!.score}/100)`,
    description:
      `"${ref.pkg}" exists, but several individually-weak signals compound into an elevated risk shape — ` +
      `the pattern of a low-adoption malicious package or patient squat that trips no single alarm. ${shape} ` +
      `Advisory assessment from package metadata, NOT a malware detection. Found in \`${ref.filename}\` at line ${ref.line}.`,
    file: ref.filename,
    line: ref.line,
    recommendation: `Review "${ref.pkg}" before trusting it — inspect its repository, maintainer history and recent releases. If your agent chose it and you can't justify it, prefer a well-established alternative.`,
    cve: "CWE-1357",
  };
}

// ─── Public entry point ────────────────────────────────────────────────────────

export async function preFlightCheck(files: FileInput[]): Promise<PreFlightResult> {
  const [secretFindings, packageFindings] = await Promise.all([
    Promise.resolve(scanSecrets(files)),
    scanPackages(files),
  ]);

  // Deduplicate on file:line:type
  const seen = new Set<string>();
  const findings: CoreFinding[] = [];
  for (const f of [...packageFindings, ...secretFindings]) {
    const key = `${f.file}:${f.line}:${f.type}`;
    if (!seen.has(key)) { seen.add(key); findings.push(f); }
  }

  const critical = findings.filter((f) => f.severity === "critical").length;
  const warnings = findings.filter((f) => f.severity === "warning").length;
  const verdict: Verdict = critical > 0 ? "BLOCKED" : warnings > 0 ? "REVIEW_REQUIRED" : "CLEAR";

  return { verdict, findings, summary: { filesChecked: files.length, critical, warnings } };
}
