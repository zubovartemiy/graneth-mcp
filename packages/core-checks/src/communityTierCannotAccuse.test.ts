/**
 * THE PROVENANCE BEHIND AN ACCUSATION IS NOT THE ACCUSED'S TO SUPPLY.
 *
 * The CRITICAL branch — '"x" is a known hallucinated name and has SINCE BEEN
 * REGISTERED', 'treat the registered package as hostile until proven otherwise'
 * — fires when the registry's first-published date is later than the date the
 * name was recorded. On the curated tiers Graneth owns that date.
 *
 * On the `community` tier an anonymous, unmoderated POST owns it: the endpoint
 * accepts any syntactically valid name whose only qualification is that it does
 * not exist YET, and its report time becomes the recorded date in the next
 * snapshot. So the accusation was armable to order — report a name a real
 * project is about to publish, wait for the publish, and every user of the npm
 * package who imports it is BLOCKED and told its author is hostile.
 *
 * That is the exact false accusation this branch was narrowed to prevent
 * (react-gpt 2015, express-ai 2016, pandas-gpt), and `recorded` only prevented
 * it while we owned the date.
 *
 * The snapshot is mocked because it carries no community rows yet — the hole
 * is closed before the first one arrives, which is the only useful time.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const registryMocks = vi.hoisted(() => ({ packageExists: vi.fn() }));
vi.mock("./registry.js", async importOriginal => {
  const actual = await importOriginal<typeof import("./registry.js")>();
  return { ...actual, packageExists: registryMocks.packageExists };
});

vi.mock("./threatSnapshot.js", () => ({
  THREAT_SNAPSHOT: [
    {
      name: "someones-real-package",
      ecosystem: "npm",
      tier: "community",
      recorded: "2026-01-01",
    },
    {
      name: "curated-ghost",
      ecosystem: "npm",
      tier: "reported",
      recorded: "2026-01-01",
    },
  ],
}));

const { preFlightCheck } = await import("./preflight.js");

/** The package exists, and was first published AFTER the name was recorded. */
function publishedAfterRecording() {
  registryMocks.packageExists.mockResolvedValue({
    exists: true,
    isNewPackage: false,
    publishedAt: new Date("2026-06-01"),
  });
}

beforeEach(() => vi.clearAllMocks());

describe("a name anybody could have put on the list", () => {
  it("does not accuse its author of squatting", async () => {
    publishedAfterRecording();

    const res = await preFlightCheck([
      { path: "app.js", content: 'import x from "someones-real-package";' },
    ]);

    const text = res.findings
      .map(f => `${f.title} ${f.recommendation}`)
      .join(" ");
    expect(text).not.toMatch(/SINCE BEEN REGISTERED/i);
    expect(text).not.toMatch(/hostile/i);
  });

  it("does not block the commit", async () => {
    publishedAfterRecording();

    const res = await preFlightCheck([
      { path: "app.js", content: 'import x from "someones-real-package";' },
    ]);

    expect(res.summary.critical).toBe(0);
    expect(res.verdict).not.toBe("BLOCKED");
  });

  it("still names the package, so the report is not wasted", async () => {
    publishedAfterRecording();

    const res = await preFlightCheck([
      { path: "app.js", content: 'import x from "someones-real-package";' },
    ]);

    expect(res.findings.map(f => f.title).join(" ")).toContain(
      "someones-real-package"
    );
  });
});

describe("a name on a tier Graneth dated itself", () => {
  it("still raises the squat accusation, which is what the branch is for", async () => {
    publishedAfterRecording();

    const res = await preFlightCheck([
      { path: "app.js", content: 'import x from "curated-ghost";' },
    ]);

    expect(res.summary.critical).toBeGreaterThan(0);
    expect(res.verdict).toBe("BLOCKED");
    expect(res.findings.map(f => f.title).join(" ")).toMatch(
      /SINCE BEEN REGISTERED/i
    );
  });
});
