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
import {
  extractImportedPackages,
  type FileInput,
  type PackageRef,
} from "./imports.js";
import {
  extractManifestPackages,
  type ManifestParseError,
} from "./manifests.js";
import {
  extractInternalNameEvidence,
  isInternalName,
} from "./internalNames.js";
import { computeDependencyRisk, isStackedRisk } from "./riskScore.js";
import { packageExists, type RegistryResult } from "./registry.js";
import { knownHallucination } from "./knownHallucinations.js";
import {
  KNOWN_SECRET_PATTERNS,
  EXAMPLE_CREDENTIALS,
  extractSecretCandidates,
  realMatches,
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
function knownPatternFindingsForLine(
  content: string,
  path: string,
  lineNo: number
): CoreFinding[] {
  const findings: CoreFinding[] = [];
  for (const p of KNOWN_SECRET_PATTERNS) {
    const { title, description, cve } = p;
    // Vendor-documented sample keys (AWS docs etc.) are real-shaped but grant
    // nothing, so a docs snippet must not block a commit. The downgrade belongs
    // to the matched value alone: report the first occurrence that is NOT one,
    // and fall back to an example only when every occurrence is one — a
    // downgrade, never a silence.
    const candidates = realMatches(content, p);
    if (candidates.length === 0) continue;
    const isExample = candidates.every(m => EXAMPLE_CREDENTIALS.has(m));
    findings.push({
      type: "hardcoded_secret",
      severity: isExample || p.severity === "warning" ? "warning" : "critical",
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
function entropyFindingForLine(
  content: string,
  path: string,
  lineNo: number
): CoreFinding | null {
  for (const { value, varName } of extractSecretCandidates(content)) {
    if (value.length < MIN_SECRET_LENGTH || value.length > MAX_SECRET_LENGTH)
      continue;

    const h = shannonEntropy(value);
    const cs = detectCharset(value);
    const { charset, threshold } = cs;
    if (h < threshold) continue;

    const confidence = computeConfidence(h, cs, varName);
    const confidencePct = Math.round(confidence * 100);
    const hasSemanticContext =
      !!varName && SEMANTIC_SECRET_KEYWORDS.some(kw => varName.includes(kw));
    if (confidence < 0.55 && !hasSemanticContext) continue;

    const charsetLabel =
      charset === "hex"
        ? "hex"
        : charset === "base64"
          ? "base64/alphanumeric"
          : "high-entropy";
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
      recommendation:
        "Move this value to an environment variable or secrets manager and regenerate it if it was ever committed.",
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

/**
 * The same, for a file a machine emitted or a third party wrote.
 *
 * `GENERATED_ARTIFACT_PATH_RE` was exported from this module under a comment
 * promising this downgrade, and only the SERVER ever called it — so the shared
 * core drifted in the exact direction its own header says it cannot: a vendored
 * bundle was a warning through the Graneth server and a commit-blocking
 * CRITICAL through the npm package, telling a user to "rotate this credential
 * immediately" about a line a bundler emitted. The free MCP tool is the surface
 * where that misfire is hardest to explain.
 *
 * Downgraded, never dropped — a real key committed into `dist/` is still a leak
 * worth seeing.
 */
function downgradeForGeneratedPath(f: CoreFinding): CoreFinding {
  if (f.severity !== "critical") return f;
  return {
    ...f,
    severity: "warning",
    description: `${f.description} Located in a generated or vendored artifact — nobody wrote this line by hand; confirm it is not a real credential.`,
  };
}

function scanSecrets(files: FileInput[]): CoreFinding[] {
  const findings: CoreFinding[] = [];

  for (const file of files) {
    const isTestPath = TEST_FIXTURE_PATH_RE.test(file.path);
    const isGeneratedPath = GENERATED_ARTIFACT_PATH_RE.test(file.path);
    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const content = lines[i];
      const lineNo = i + 1;
      const trimmed = content.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#"))
        continue;

      let lineFindings = knownPatternFindingsForLine(
        content,
        file.path,
        lineNo
      );
      const entropyFinding = entropyFindingForLine(content, file.path, lineNo);
      if (entropyFinding) lineFindings = [...lineFindings, entropyFinding];
      // Test path first, then generated — same first-reason-wins ordering the
      // server uses, so a file that is both reads the same either side.
      if (isTestPath) lineFindings = lineFindings.map(downgradeForTestPath);
      else if (isGeneratedPath)
        lineFindings = lineFindings.map(downgradeForGeneratedPath);
      findings.push(...lineFindings);
    }
  }
  return findings;
}

// ─── Package existence scan ────────────────────────────────────────────────────

/** Human-readable registry name + site per ecosystem (six registries). */
const REGISTRY_LABEL: Record<string, { name: string; site: string }> = {
  npm: { name: "npm", site: "npmjs.com" },
  pypi: { name: "PyPI", site: "pypi.org" },
  crates: { name: "crates.io", site: "crates.io" },
  gems: { name: "RubyGems", site: "rubygems.org" },
  go: { name: "the Go module proxy", site: "pkg.go.dev" },
  composer: { name: "Packagist", site: "packagist.org" },
};

function registryLabel(eco: string): { name: string; site: string } {
  return REGISTRY_LABEL[eco] ?? { name: eco, site: eco };
}

/**
 * How many registry lookups one `pre_flight_check` may make, and how long it
 * may spend making them.
 *
 * 1,000 at a concurrency of 8 is ~125 sequential batches — well beyond any
 * honest commit and far short of the hundreds of thousands a generated
 * manifest inside the documented input limits could otherwise demand. The
 * clock is the second half: a registry that answers slowly rather than not at
 * all cannot be bounded by a count.
 */
export const MAX_REGISTRY_LOOKUPS = 1000;
export const LOOKUP_BUDGET_MS = 60_000;

/** Honest fail-open marker: existence is UNKNOWN, so the result must say so —
 *  a warning (REVIEW_REQUIRED), never a commit-blocking critical, and never a
 *  silent CLEAR (the fail-safe contract). */
function unreachableFinding(
  pkg: string,
  eco: string,
  file: string,
  line: number
): CoreFinding {
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

/**
 * Every package this payload refers to, from both sources, minus the ones the
 * payload itself proves are internal.
 *
 * ── ONE FILTER, BOTH PATHS ──────────────────────────────────────────────────
 * Issue #152: tsconfig path aliases and workspace packages are valid-looking
 * names that 404 by design. When the payload carries the EVIDENCE (tsconfig
 * paths, the manifest's own name, `workspace:` deps) such names are internal,
 * not hallucinations. No evidence → detection stays on.
 *
 * That filter used to be applied to IMPORT-derived refs and skipped for
 * MANIFEST-derived ones, so one package produced opposite outcomes depending
 * on which line of the repository mentioned it. `npmDependencyTarget` drops
 * only `workspace:`/`file:`/`link:`/`portal:`/`catalog:`/git/URL specifiers, so
 * an internal package pinned to a plain semver range — the normal shape in a
 * workspace or behind a private `.npmrc` scope — went straight through: sent in
 * the URL path to registry.npmjs.org, and its 404 returned as a CRITICAL
 * calling the customer's own private package the hallmark of an AI
 * hallucination.
 */
function collectPackageRefs(files: FileInput[]): {
  refs: PackageRef[];
  manifestErrors: ManifestParseError[];
  /**
   * What the diff let `isInternalName` learn — tsconfig `paths` keys, manifest
   * names, `workspace:` specs.
   *
   * Returned rather than reduced to a boolean because "a manifest was present"
   * is not the same question as "the thing that would have resolved THIS name
   * was present". Measured: after the first version of this rule, four
   * production criticals survived on `@shared/const` — in commits that happened
   * to touch `packages/mcp-server/package.json`, which says nothing whatever
   * about the `@shared` scope. Presence of some evidence is not evidence.
   */
  evidence: ReturnType<typeof extractInternalNameEvidence>;
} {
  const evidence = extractInternalNameEvidence(files);
  const internal = (r: PackageRef) =>
    r.ecosystem === "npm" && isInternalName(r.pkg, evidence);

  // Typed as `PackageRef[]`, not inferred: `.map` narrows `source` to the
  // literal `"import"`, and the manifest push below is then a type error rather
  // than the union this list is supposed to be.
  const refs: PackageRef[] = extractImportedPackages(files)
    .filter(r => !internal(r))
    .map(r => ({ ...r, source: "import" as const }));

  // Manifest-declared dependencies (package.json / requirements.txt) — the
  // most common way AI agents add packages; import statements alone miss them.
  const manifest = extractManifestPackages(files);
  const seen = new Set(refs.map(r => `${r.pkg}::${r.ecosystem}`));
  for (const ref of manifest.refs) {
    const key = `${ref.pkg}::${ref.ecosystem}`;
    if (internal(ref) || seen.has(key)) continue;
    seen.add(key);
    refs.push({ ...ref, source: "manifest" as const });
  }

  return { refs, manifestErrors: manifest.errors, evidence };
}

/**
 * Was the diff carrying anything that speaks to THIS name?
 *
 * For a scoped name, only evidence mentioning the same scope counts — a
 * manifest from an unrelated workspace package proves nothing about
 * `@shared`. Measured: asking only "was any manifest present" left four false
 * criticals alive, in commits that happened to touch an unrelated package.json.
 */
function evidenceSpeaksTo(
  pkg: string,
  evidence: ReturnType<typeof extractInternalNameEvidence>
): boolean {
  const scope = pkg.startsWith("@") ? pkg.split("/")[0] + "/" : null;
  if (!scope) return evidence.exact.size > 0 || evidence.prefixes.length > 0;
  if ([...evidence.exact].some(n => n.startsWith(scope))) return true;
  return evidence.prefixes.some(pre => pre.startsWith(scope));
}

/**
 * May a registry 404 on this reference BLOCK the commit?
 *
 * Lifted out of `scanPackages` when the rule pushed it past the complexity
 * ceiling — which is the ceiling working as intended: this is a decision with
 * its own reasoning, and it reads better where the reasoning fits.
 *
 * Three ways the answer is yes, and the third came from measurement.
 *
 * DECLARED — the name is in a manifest. Somebody wrote it down as a dependency
 * and the registry does not have it. A fact about the diff.
 *
 * UNSCOPED — a bare name is not a tsconfig alias. Over this repository history
 * every one of 76 false production criticals carried a scope, and every name
 * that must still block was bare. Aliases and monorepos use invented scopes
 * because a scope is cheap and unregistered. This is what keeps "a ghost
 * package in a test file still blocks" intact, for its own reason: an import
 * precedes the install, and catching it there is what a pre-flight check is.
 *
 * RESOLVED AND REFUSED — the diff carried evidence about this very scope and
 * `isInternalName` still said no. A real answer.
 *
 * Otherwise the checker could not decide, and says so instead of guessing.
 */
function ghostPackageCanBlock(
  ref: PackageRef,
  evidence: ReturnType<typeof extractInternalNameEvidence>
): boolean {
  if (ref.source === "manifest") return true;
  // An import specifier is the distribution name only in npm. Elsewhere the two
  // namespaces differ by design — `import yaml` is PyYAML, `import pptx` is
  // python-pptx, `use serde_json` is the crate `serde-json`, a PHP namespace is
  // not a Composer package — so a 404 on the imported name says nothing about
  // the dependency and cannot block. The manifest still can, above.
  if (ref.ecosystem !== "npm") return false;
  if (!ref.pkg.startsWith("@")) return true;
  return evidenceSpeaksTo(ref.pkg, evidence);
}

/**
 * The finding for a package the registry does not have.
 *
 * Extracted from `scanPackages` when the severity rule pushed that function
 * past the complexity ceiling. The ceiling was right: this is a decision with
 * its own reasoning and a paragraph explaining it, and both belong somewhere
 * a reader can take in at once.
 */
function ghostPackageFinding(
  ref: PackageRef,
  registryName: string,
  evidence: ReturnType<typeof extractInternalNameEvidence>
): CoreFinding {
  // ── ONLY A DECLARED DEPENDENCY IS DEMONSTRABLE ──────────────────────
  //
  // A name in a MANIFEST is one somebody wrote down as a dependency; the
  // registry not having it is a fact about the diff. A bare IMPORT
  // specifier is not: it may be a path alias, a workspace package or a
  // typo, and `isInternalName` can only tell them apart when the diff
  // carries the evidence — `tsconfig.json`, a workspace manifest — which
  // a pull request almost never does. The published tool's own contract
  // is "files staged for commit".
  //
  // Measured over this repository's history before this line existed:
  // 76 production-path criticals, every one an internal name reached
  // through an import, every one of which would have auto-rejected a
  // legitimate pull request. The name is still reported; what changed is
  // the claim made about it.
  const declared = ref.source === "manifest";
  const canDecide = ghostPackageCanBlock(ref, evidence);
  // Outside npm an imported name and a distribution name are different things,
  // so the honest headline is about the name, not about a missing package.
  const importNameGap = !declared && ref.ecosystem !== "npm";
  return {
    type: "ghost_package",
    severity: canDecide ? "critical" : "warning",
    title: importNameGap
      ? `Imported name "${ref.pkg}" is not a package name on ${registryName}`
      : `Package "${ref.pkg}" does not exist in ${registryName}`,
    description:
      (importNameGap
        ? `\`${ref.filename}\` imports "${ref.pkg}", and ${registryName} has no package under that name. In this ecosystem the import name and the distribution name are routinely different — \`import yaml\` comes from PyYAML, \`import pptx\` from python-pptx — so this is reported, not blocked. The manifest is what settles it: include it in the check. `
        : declared
          ? `"${ref.pkg}" is declared as a dependency and is not a real package — verified live against ${registryName} (404). `
          : `"${ref.pkg}" is imported here and ${registryName} does not have it (404). The name carries a scope, and this diff does not include the \`tsconfig.json\` or \`package.json\` that would say whether that scope is a path alias or a workspace package — so this is reported rather than blocked. Include those files in the check to get a definitive answer. `) +
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
  };
}

async function scanPackages(files: FileInput[]): Promise<CoreFinding[]> {
  const { refs, manifestErrors, evidence } = collectPackageRefs(files);

  // Fail-safe: an unreadable manifest must surface as a finding, never as a
  // silent "clean" (its dependencies were NOT verified).
  const findings: CoreFinding[] = manifestErrors.map(e => ({
    type: "manifest_unparsable",
    severity: "warning" as const,
    title: `Could not parse ${e.file} — its dependencies were NOT verified`,
    description: `\`${e.file}\` could not be parsed (${e.message}), so its dependencies were not checked against the registry. This diff is not known-clean.`,
    file: e.file,
    line: 1,
    recommendation:
      "Fix the manifest syntax and re-run the check before committing.",
  }));

  if (refs.length === 0) return findings;

  const CONCURRENCY = 8;

  // ── THE CALL AS A WHOLE IS BOUNDED, NOT ONLY EACH REQUEST ──────────────────
  //
  // Every fetch already carries its own 5–10 s AbortSignal, and nothing
  // bounded the SUM. Wall time was `ceil(refs / 8) × batch latency` with no
  // limit on `refs`, and the MCP handler awaits this with no timeout of its
  // own — so a payload comfortably inside the documented 50-file / 200,000-
  // character limits could issue hundreds of thousands of lookups and simply
  // never answer. The editor's agent waits forever on a response id that never
  // arrives, and the burst leaves from the USER's address, which is how a
  // public registry rate-limits or blocks them.
  //
  // Reachable without hostility: 50 requirements files of a few hundred
  // dependencies each is an ordinary monorepo.
  //
  // Anything past the budget is NOT silently dropped. It becomes the same
  // fail-safe warning an unreachable registry produces, which says in as many
  // words that existence is UNKNOWN and the result is not a verified-clean —
  // the one thing this file refuses to do is turn an unchecked package into a
  // CLEAR.
  const skipped: typeof refs = refs.splice(MAX_REGISTRY_LOOKUPS);
  const deadline = Date.now() + LOOKUP_BUDGET_MS;

  for (let i = 0; i < refs.length; i += CONCURRENCY) {
    if (Date.now() > deadline) {
      skipped.push(...refs.slice(i));
      break;
    }
    const batch = refs.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async ref => ({
        ref,
        signal: await packageExists(ref.pkg, ref.ecosystem),
      }))
    );

    for (let j = 0; j < results.length; j++) {
      const r = results[j];
      if (r.status !== "fulfilled") {
        // A crashed lookup is UNKNOWN, not clean — surface it (fail-safe).
        const ref = batch[j];
        findings.push(
          unreachableFinding(ref.pkg, ref.ecosystem, ref.filename, ref.line)
        );
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
        findings.push(
          unreachableFinding(ref.pkg, ref.ecosystem, ref.filename, ref.line)
        );
      } else if (!signal.exists) {
        findings.push(ghostPackageFinding(ref, registryName, evidence));
      } else if (signal.isNewPackage) {
        const age = signal.publishedAt
          ? Math.floor(
              (Date.now() - signal.publishedAt.getTime()) /
                (24 * 60 * 60 * 1000)
            )
          : null;
        const ageStr =
          age !== null ? `${age} day${age !== 1 ? "s" : ""} ago` : "recently";
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

  // Everything the budget cut, said out loud. Same warning an unreachable
  // registry earns — REVIEW_REQUIRED, never a critical, and never a silent
  // CLEAR.
  for (const ref of skipped) {
    findings.push(
      unreachableFinding(ref.pkg, ref.ecosystem, ref.filename, ref.line)
    );
  }
  // ── AND THE PATH DOWNGRADES DELIBERATELY DO NOT APPLY HERE ────────────────
  //
  // A first attempt extended `scanSecrets`'s test-path downgrade to this scan,
  // on the measurement that 92 of this repository's criticals were on test
  // files. `preflight.test.ts` refused it — "still BLOCKS ghost packages even
  // in test files" — and that test is right for a reason the measurement did
  // not contain: a secret in a test file is inert data, and a package
  // reference in a test file is a REAL DEPENDENCY. The package manager
  // installs it and its install scripts run, wherever the import sits.
  //
  // The 92 disappear anyway, because they were fixture text rather than
  // dependencies, and the manifest-versus-import rule above is what
  // distinguishes those correctly. Two fixes were tried; only one was needed,
  // and the other would have taught the checker to ignore the file type
  // attackers would then use.
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

function knownHallucinationFinding(
  ref: PackageRef,
  signal: RegistryResult,
  registryName: string
): CoreFinding | null {
  const known = knownHallucination(ref.pkg, ref.ecosystem);
  if (!known) return null;

  const exists = !signal.unreachable && signal.exists;
  const firstPublished = signal.publishedAt
    ? signal.publishedAt.toISOString().slice(0, 10)
    : null;
  // ── AND THE PROVENANCE IS NOT THE ACCUSED'S TO SUPPLY ──────────────────────
  //
  // `recorded` is what makes this branch narrow: the package was published
  // AFTER we wrote the name down. On the curated tiers we control that date.
  // On the `community` tier an anonymous, unmoderated POST does — the endpoint
  // accepts any syntactically valid name whose only qualification is that it
  // does not exist yet, and `reportedAt` becomes `recorded` in the next
  // snapshot.
  //
  // So the accusation was armable on demand: report a name a real project is
  // about to publish, wait for the publish, and every user of the npm package
  // who imports it gets BLOCKED and is told to treat its author as hostile.
  // That is the exact false accusation the comment above records this branch
  // being narrowed to prevent (react-gpt 2015, express-ai 2016, pandas-gpt) —
  // and `recorded` only prevents it while WE own the date.
  //
  // Community rows fall through to the warning branch below: still named,
  // still worth confirming, no squat claim and no BLOCKED.
  const registeredSince =
    exists &&
    known.tier !== "community" &&
    !!known.recorded &&
    !!firstPublished &&
    firstPublished > known.recorded;

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

  // UNREACHABLE IS NOT ABSENT.
  //
  // `packageExists` fails open with `{exists:true, unreachable:true}`, and the
  // `exists` computed above ands that away — so a registry that could not be
  // reached became indistinguishable from a 404 and fell into the branch below,
  // which states "It does not exist on npm today" as a verified fact. Nothing
  // verified it. And because a known-hallucination finding short-circuits the
  // loop, the honest `registry_unreachable` warning was skipped too, inverting
  // the fail-safe this file states in as many words: unknown existence is a
  // warning, never a commit-blocking critical, and never a claim the code did
  // not check.
  //
  // The listed name is still surfaced — the list is local and does not need the
  // network — but the sentence stops asserting what the network did not answer.
  if (signal.unreachable) {
    return {
      type: "known_hallucination",
      severity: "warning",
      title: `"${ref.pkg}" is on Graneth's hallucinated-name list — and ${registryName} was unreachable`,
      description: `"${ref.pkg}" is in Graneth's public threat feed (${known.tier} tier): ${provenanceClause(known.tier)}. ${registryName} could not be reached, so whether a package exists under that name today is UNKNOWN — this is NOT a verified-clean and NOT a verified-absent. Found in \`${ref.filename}\` at line ${ref.line}.`,
      file: ref.filename,
      line: ref.line,
      recommendation: `Re-run when the network is available. Until then, do not install "${ref.pkg}". The full feed: https://graneth.com/api/threat-feed`,
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
function dependencyRiskShapeFinding(
  ref: PackageRef,
  signal: RegistryResult
): CoreFinding | null {
  if (!signal.exists || signal.unreachable) return null;
  const risk = computeDependencyRisk({
    exists: true,
    isNewPackage: signal.isNewPackage,
    ageDays: signal.publishedAt
      ? Math.floor((Date.now() - signal.publishedAt.getTime()) / 86_400_000)
      : null,
    hasRepository: signal.hasRepository,
    hasProvenance: signal.hasProvenance,
    hasInstallScripts: signal.hasInstallScripts,
    isDeprecated: signal.isDeprecated,
  });
  if (!isStackedRisk(risk)) return null;
  const shape = risk!.factors
    .filter(f => f.points > 0)
    .map(f => f.note)
    .join(" ");
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

export async function preFlightCheck(
  files: FileInput[]
): Promise<PreFlightResult> {
  const [secretFindings, packageFindings] = await Promise.all([
    Promise.resolve(scanSecrets(files)),
    scanPackages(files),
  ]);

  // ── DEDUPLICATE ON THE SUBJECT, NOT ONLY ON THE LOCATION ──────────────────
  //
  // The key was `file:line:type`, and a manifest is exactly where that
  // collides: every dependency of a one-line package.json is reported at line
  // 1, so two DIFFERENT hallucinated packages declared in the same file became
  // one finding. The second was silently dropped, the critical count came out
  // one lower than the truth, and a verdict that should have named two names
  // named one. A generated or minified manifest collapses a whole dependency
  // list into a single report.
  //
  // The title carries the subject — the package name, the credential's
  // variable — so including it separates genuinely distinct findings while
  // still collapsing the true duplicates this was written for.
  const seen = new Set<string>();
  const findings: CoreFinding[] = [];
  for (const f of [...packageFindings, ...secretFindings]) {
    const key = `${f.file}:${f.line}:${f.type}:${f.title}`;
    if (!seen.has(key)) {
      seen.add(key);
      findings.push(f);
    }
  }

  const critical = findings.filter(f => f.severity === "critical").length;
  const warnings = findings.filter(f => f.severity === "warning").length;
  const verdict: Verdict =
    critical > 0 ? "BLOCKED" : warnings > 0 ? "REVIEW_REQUIRED" : "CLEAR";

  return {
    verdict,
    findings,
    summary: { filesChecked: files.length, critical, warnings },
  };
}
