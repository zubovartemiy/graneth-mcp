/**
 * A BLOCKED VERDICT MUST SHOW WHAT BLOCKED IT.
 *
 * The listing handed back to the agent is capped at 20, and the verdict is
 * computed over ALL findings — so twenty warnings arriving ahead of one
 * critical produced BLOCKED with nothing critical listed. The file and line of
 * the thing that stopped the commit were withheld from the only reader who
 * could act on them, and the agent was left to relay "do not commit" with no
 * reason attached.
 *
 * Its own file because it mocks the detection core, which the rest of
 * `tools.test.ts` deliberately runs for real.
 */
import { describe, it, expect, vi } from "vitest";

const core = vi.hoisted(() => ({ preFlightCheck: vi.fn() }));
vi.mock("../../core-checks/src/index.js", () => ({
  preFlightCheck: core.preFlightCheck,
}));

const { runPreFlightCheck, MAX_LISTED_FINDINGS } = await import("./tools.js");

const warn = (i: number) => ({
  severity: "warning" as const,
  type: "new_package_risk",
  title: `warning ${i}`,
  file: "a.ts",
  line: i,
  description: "",
  recommendation: "",
});

const crit = {
  severity: "critical" as const,
  type: "ghost_package",
  title: "the one that blocks",
  file: "b.ts",
  line: 1,
  description: "",
  recommendation: "",
};

function answer(findings: unknown[], verdict = "BLOCKED") {
  core.preFlightCheck.mockResolvedValue({
    verdict,
    findings,
    summary: { filesChecked: 1, critical: 1, warnings: findings.length - 1 },
  });
}

describe("the findings that come back with a verdict", () => {
  it("lists the critical even when the cap's worth of warnings arrived first", async () => {
    answer([...Array.from({ length: 25 }, (_, i) => warn(i)), crit]);

    const out = await runPreFlightCheck([], undefined);

    expect(out.findings).toHaveLength(MAX_LISTED_FINDINGS);
    expect(out.findings.map(f => f.title)).toContain("the one that blocks");
  });

  it("puts every critical ahead of every warning", async () => {
    answer([warn(1), crit, warn(2), { ...crit, title: "second critical" }]);

    const out = await runPreFlightCheck([], undefined);

    expect(out.findings.slice(0, 2).map(f => f.severity)).toEqual([
      "critical",
      "critical",
    ]);
  });

  it("keeps the original order within a severity", async () => {
    // The sort must be stable, or a reader loses the file-by-file ordering the
    // scan produced.
    answer([warn(1), warn(2), warn(3)], "REVIEW_REQUIRED");

    const out = await runPreFlightCheck([], undefined);

    expect(out.findings.map(f => f.line)).toEqual([1, 2, 3]);
  });

  it("does not reorder when nothing is truncated and nothing is critical", async () => {
    answer([warn(9), warn(4), warn(7)], "REVIEW_REQUIRED");

    const out = await runPreFlightCheck([], undefined);

    expect(out.findings.map(f => f.line)).toEqual([9, 4, 7]);
  });
});
