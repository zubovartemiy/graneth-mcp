/**
 * AI-introduced-dependency risk score — the "stack-catch": a dependency an AI
 * agent chose that is individually unremarkable on several axes but collectively
 * carries the risk SHAPE attackers exploit. NOT a malware verdict — a composite
 * of falsifiable signals, computed at generation time.
 */
import { describe, it, expect } from "vitest";
import { computeDependencyRisk, isStackedRisk } from "./riskScore.js";

/**
 * A score, or a failure that says the contract was broken.
 *
 * `computeDependencyRisk` returns `Risk | null` on purpose — `null` is "we could
 * not establish existence", the same fail-safe answer the rest of this product
 * gives. So a test that wants the score has to say it expected one, rather than
 * dereferencing a value the signature says may not be there.
 *
 * Written as a helper rather than `r!` because the two read differently to the
 * next person: `!` says "the checker is wrong", this says "null here is a
 * regression in the thing under test".
 */
function scored(r: ReturnType<typeof computeDependencyRisk>): NonNullable<typeof r> {
  expect(r, "expected a score — null means existence could not be established").not.toBeNull();
  return r as NonNullable<typeof r>;
}

describe("computeDependencyRisk", () => {
  it("a nonexistent package is maximal risk (the ghost/hallucination case)", () => {
    const r = scored(computeDependencyRisk({ exists: false }));
    expect(r.score).toBe(100);
    expect(r.band).toBe("critical");
    expect(r.factors.some((f) => /does not exist/i.test(f.note))).toBe(true);
  });

  it("existence UNKNOWN (registry unreachable) is not scored as safe — returns null", () => {
    const r = computeDependencyRisk({ exists: true, unreachable: true });
    expect(r).toBeNull();
  });

  it("a real, popular, provenance-backed package is minimal risk (no false alarm)", () => {
    const r = computeDependencyRisk({
      exists: true, isNewPackage: false, weeklyDownloads: 5_000_000,
      hasRepository: true, hasProvenance: true, maintainersCount: 1,
    })!;
    expect(r.band).toBe("minimal");
    expect(r.score).toBeLessThan(25);
  });

  it("an established modest package (repo + old + real adoption) is minimal — no FP on the long tail", () => {
    const r = computeDependencyRisk({
      exists: true, isNewPackage: false, weeklyDownloads: 20_000,
      hasRepository: true, hasProvenance: false, maintainersCount: 2,
    })!;
    expect(r.band).toBe("minimal");
  });

  it("THE STACK-CATCH: 5 individually-weak signals compound into a HIGH band", () => {
    // none of these alone trips a critical today — but together they are the
    // shape of a patient squat / malicious low-adoption package.
    const r = computeDependencyRisk({
      exists: true, isNewPackage: true, ageDays: 12,
      weeklyDownloads: 30, hasRepository: false, hasProvenance: false,
      maintainersCount: 1,
    })!;
    expect(r.score).toBeGreaterThanOrEqual(50);
    expect(["high", "critical"]).toContain(r.band);
    // must be explainable — every contributing signal named
    expect(r.factors.length).toBeGreaterThanOrEqual(4);
  });

  it("the npm dropper shape (new + install scripts + low adoption) is high", () => {
    const r = computeDependencyRisk({
      exists: true, isNewPackage: true, hasInstallScripts: true, weeklyDownloads: 5,
    })!;
    expect(r.score).toBeGreaterThanOrEqual(50);
    expect(r.factors.some((f) => /install script/i.test(f.note))).toBe(true);
  });

  it("install scripts on an established high-adoption package do NOT dominate (esbuild-shape)", () => {
    const r = computeDependencyRisk({
      exists: true, isNewPackage: false, hasInstallScripts: true,
      weeklyDownloads: 30_000_000, hasRepository: true, hasProvenance: true,
    })!;
    expect(r.band).toBe("minimal");
  });

  it("a 1-edit typosquat neighbour is high even if it technically exists", () => {
    const r = computeDependencyRisk({ exists: true, typosquatDistance: 1, weeklyDownloads: 40 })!;
    expect(r.score).toBeGreaterThanOrEqual(50);
  });

  it("provenance attestation is a real mitigator (lifts an otherwise-elevated package down)", () => {
    const without = computeDependencyRisk({ exists: true, isNewPackage: false, weeklyDownloads: 200, hasRepository: false, hasProvenance: false })!;
    const withProv = computeDependencyRisk({ exists: true, isNewPackage: false, weeklyDownloads: 200, hasRepository: false, hasProvenance: true })!;
    expect(withProv.score).toBeLessThan(without.score);
  });

  it("score is always clamped to 0..100 and band matches", () => {
    const r = computeDependencyRisk({
      exists: true, isSecurityHolding: true, knownHallucination: true,
      typosquatDistance: 1, isNewPackage: true, hasInstallScripts: true,
      weeklyDownloads: 0, hasRepository: false, isDeprecated: true, maintainersCount: 1,
    })!;
    expect(r.score).toBeLessThanOrEqual(100);
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.band).toBe("critical");
  });

  it("a deprecated but popular package is at most elevated — deprecation alone is not a panic", () => {
    const r = computeDependencyRisk({
      exists: true, isNewPackage: false, isDeprecated: true,
      weeklyDownloads: 2_000_000, hasRepository: true,
    })!;
    expect(["minimal", "elevated"]).toContain(r.band);
  });
});

describe("isStackedRisk — isolates the compounding shape from single dominant signals", () => {
  it("true for a genuine stack (no single signal reaches the high threshold)", () => {
    const r = computeDependencyRisk({
      exists: true, isNewPackage: true, weeklyDownloads: 30,
      hasRepository: false, maintainersCount: 1,
    });
    expect(isStackedRisk(r)).toBe(true);
  });

  it("false for a single dominant signal (security holding) — it has its own finding", () => {
    const r = computeDependencyRisk({ exists: true, isSecurityHolding: true });
    expect(r!.band).not.toBe("minimal");
    expect(isStackedRisk(r)).toBe(false);
  });

  it("false for a confident typosquat — its own finding already fires", () => {
    const r = computeDependencyRisk({ exists: true, typosquatDistance: 1 });
    expect(isStackedRisk(r)).toBe(false);
  });

  it("false for a nonexistent package (ghost has its own critical)", () => {
    expect(isStackedRisk(computeDependencyRisk({ exists: false }))).toBe(false);
  });

  it("false for minimal/elevated bands", () => {
    expect(isStackedRisk(computeDependencyRisk({ exists: true, isDeprecated: true, weeklyDownloads: 500, hasRepository: false }))).toBe(false);
  });
});
