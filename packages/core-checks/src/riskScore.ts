/**
 * AI-introduced-dependency risk score.
 *
 * The registry existence check answers "is this a real package?" (commodity —
 * everyone can 404-check). This answers the harder, non-commodity question at
 * the moment an AI agent introduces a dependency: **does this real package
 * carry the risk SHAPE attackers exploit?** — computed by COMPOUNDING signals
 * that are individually unremarkable. A brand-new + single-maintainer +
 * no-provenance + low-adoption + no-repo package trips no single critical
 * today, yet together that is exactly the shape of a patient squat or a
 * low-adoption malicious package an AI reproduced from stale training data.
 *
 * This is NOT a malware verdict. Every input is a falsifiable metadata signal;
 * the output is an explainable, advisory risk shape. We never claim to detect a
 * backdoor in a legitimately-existing package — that is out of model.
 *
 * Mitigators (provenance attestation, high adoption, established+repo) pull the
 * score down so the long tail of real, modest packages does not false-alarm.
 */

export interface RiskSignals {
  /** Whether the package exists in its registry. */
  exists: boolean;
  /** Registry could not be reached — existence UNKNOWN, so risk is unscored. */
  unreachable?: boolean;
  /** First published < 30 days ago. */
  isNewPackage?: boolean;
  /** Age in days since first publish (alternative source for "new"). */
  ageDays?: number | null;
  /** Downloads in the trailing window; null = unknown (not penalized). */
  weeklyDownloads?: number | null;
  /** Package metadata links a source repository. */
  hasRepository?: boolean;
  /** Registry-verified build provenance attestation (SLSA). Strong legitimacy. */
  hasProvenance?: boolean;
  /** Latest version declares a preinstall/install/postinstall script. */
  hasInstallScripts?: boolean;
  /** Latest version carries a deprecation notice. */
  isDeprecated?: boolean;
  /** Registry seized the name after a malware incident (npm security holding). */
  isSecurityHolding?: boolean;
  /** Registered maintainer count; 1 = single point of compromise. */
  maintainersCount?: number | null;
  /** Name appears in the known-AI-hallucinations corpus but now resolves. */
  knownHallucination?: boolean;
  /** Edit distance to the nearest popular package name, when within the
   *  typosquat band (1 or 2); null/undefined = not a near-miss. */
  typosquatDistance?: number | null;
}

export type RiskBand = "minimal" | "elevated" | "high" | "critical";

export interface RiskFactor {
  signal: string;
  points: number;
  note: string;
}

export interface DependencyRisk {
  /** 0–100 composite risk-shape score. */
  score: number;
  band: RiskBand;
  /** Explainable breakdown — every signal that moved the score, mitigators included. */
  factors: RiskFactor[];
}

const LOW_ADOPTION = 1_000;
const VERY_LOW_ADOPTION = 50;
const HIGH_ADOPTION = 100_000;
const VERY_HIGH_ADOPTION = 1_000_000;
const ESTABLISHED_ADOPTION = 5_000;

function bandOf(score: number): RiskBand {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "elevated";
  return "minimal";
}

function isNew(s: RiskSignals): boolean {
  return s.isNewPackage === true || (s.ageDays != null && s.ageDays < 30);
}

type Add = (signal: string, points: number, note: string) => void;

/** Strong shapes — each usually already emits its own finding; they also feed
 *  the composite so a stack that includes one still lands correctly. */
function applyDominantSignals(s: RiskSignals, add: Add): void {
  if (s.isSecurityHolding)
    add(
      "security_holding",
      70,
      "Registry seized this name after a malware/typosquat incident."
    );
  if (s.knownHallucination)
    add(
      "known_hallucination",
      45,
      "Name appears in the known-AI-hallucination corpus and has since been registered (slopsquat)."
    );
  if (s.typosquatDistance === 1)
    add(
      "typosquat_1",
      55,
      "One edit away from a hugely popular package name (typosquat shape)."
    );
  else if (s.typosquatDistance === 2)
    add(
      "typosquat_2",
      35,
      "Two edits away from a popular package name (possible typosquat)."
    );
}

/** The compounding weak signals — this is the stack-catch. */
function applyCompoundingSignals(
  s: RiskSignals,
  add: Add,
  newPkg: boolean,
  dl: number | null | undefined
): void {
  const lowAdoption = dl != null && dl < LOW_ADOPTION;
  const veryLowAdoption = dl != null && dl < VERY_LOW_ADOPTION;
  if (newPkg)
    add(
      "new_package",
      22,
      "Published within the last 30 days — the pre-registration attack window."
    );
  if (s.hasInstallScripts) {
    if (newPkg || lowAdoption)
      add(
        "install_script_risk",
        30,
        "Runs an install script AND is new / near-zero adoption — the npm dropper shape."
      );
    else
      add(
        "install_script",
        5,
        "Runs an install script (common for native builds; low risk on an established package)."
      );
  }
  if (s.isDeprecated)
    add(
      "deprecated",
      15,
      "Deprecated by its maintainer — unpatched and a name-takeover target."
    );
  if (veryLowAdoption)
    add(
      "very_low_adoption",
      28,
      "Near-zero adoption — no crowd has vetted this dependency."
    );
  else if (lowAdoption) add("low_adoption", 15, "Low adoption for its age.");
  if (s.hasRepository === false)
    add("no_repository", 12, "No linked source repository to inspect.");
  if (s.maintainersCount === 1)
    add(
      "single_maintainer",
      8,
      "Single maintainer — one account compromise ships to every consumer."
    );
}

/** Mitigators — keep the modest-but-real long tail out of the alarm. */
function applyMitigators(
  s: RiskSignals,
  add: Add,
  newPkg: boolean,
  dl: number | null | undefined
): void {
  if (s.hasProvenance)
    add(
      "provenance",
      -25,
      "Registry-verified build provenance (public CI from a public repo) — strong legitimacy."
    );
  if (dl != null && dl > VERY_HIGH_ADOPTION)
    add(
      "very_high_adoption",
      -50,
      "Very high adoption — extensively used and watched."
    );
  else if (dl != null && dl > HIGH_ADOPTION)
    add("high_adoption", -35, "High adoption — widely used.");
  if (
    !newPkg &&
    s.hasRepository === true &&
    dl != null &&
    dl >= ESTABLISHED_ADOPTION
  ) {
    add(
      "established",
      -15,
      "Established: aged, repo-backed, with real adoption."
    );
  }
}

/**
 * Compute the composite risk shape for a dependency.
 *  - nonexistent → 100 / critical (the hallucination case)
 *  - existence unknown (unreachable) → null (cannot score; caller surfaces the
 *    honest "could not verify" separately)
 *  - otherwise → compounded advisory score with an explainable factor list.
 */
export function computeDependencyRisk(s: RiskSignals): DependencyRisk | null {
  if (s.unreachable) return null;
  if (!s.exists) {
    return {
      score: 100,
      band: "critical",
      factors: [
        {
          signal: "nonexistent",
          points: 100,
          note: "Package does not exist in its registry (AI-hallucinated / ghost).",
        },
      ],
    };
  }

  const factors: RiskFactor[] = [];
  const add: Add = (signal, points, note) => {
    factors.push({ signal, points, note });
  };
  const newPkg = isNew(s);
  const dl = s.weeklyDownloads;

  applyDominantSignals(s, add);
  applyCompoundingSignals(s, add, newPkg, dl);
  applyMitigators(s, add, newPkg, dl);

  const raw = factors.reduce((sum, f) => sum + f.points, 0);
  const score = Math.max(0, Math.min(100, raw));
  return { score, band: bandOf(score), factors };
}

/**
 * True when a high/critical score is the product of COMPOUNDING weak signals
 * rather than one dominant signal that already emits its own finding (a ghost,
 * a security-holding name, a confident typosquat). This isolates the composite
 * score's unique value — the non-obvious stacked shape — so surfacing it never
 * just restates a finding the pipeline already raised.
 */
export function isStackedRisk(risk: DependencyRisk | null): boolean {
  if (!risk || (risk.band !== "high" && risk.band !== "critical")) return false;
  const maxPositive = Math.max(
    0,
    ...risk.factors.filter(f => f.points > 0).map(f => f.points)
  );
  return maxPositive < 50;
}
