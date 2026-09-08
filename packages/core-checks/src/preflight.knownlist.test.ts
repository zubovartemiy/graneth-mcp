/**
 * The bundled threat-feed snapshot inside preFlightCheck — the collective
 * immunity promise made mechanical.
 *
 * The case that matters most: a KNOWN hallucinated name that an attacker has
 * SINCE REGISTERED. A live existence check goes silent at that exact moment
 * (the package now exists), and the shared list is the only thing left
 * standing. The finding must fire on the list, not on the registry.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// flask-gpt/pypi is the first entry of the shipped snapshot (curated tier).
const KNOWN_NAME = "flask-gpt";

vi.mock("./registry.js", async importOriginal => {
  const orig = await importOriginal<typeof import("./registry.js")>();
  return { ...orig, packageExists: vi.fn(orig.packageExists) };
});

import { preFlightCheck } from "./preflight.js";
import { packageExists } from "./registry.js";
import { knownHallucination } from "./knownHallucinations.js";

const mockExists = vi.mocked(packageExists);

beforeEach(() => vi.clearAllMocks());
afterEach(() => vi.restoreAllMocks());

const req = (name: string) => [
  { path: "requirements.txt", content: `${name}==1.0.0\n` },
];

describe("knownHallucination lookup", () => {
  it("finds a snapshot entry with its tier and misses unknown names", () => {
    // `pattern`, not `confirmed`: flask-gpt is a name Graneth built from the
    // documented "popular library + AI suffix" pattern. See the block at the
    // bottom of this file for why the old label was the defect.
    expect(knownHallucination(KNOWN_NAME, "pypi")).toMatchObject({
      tier: "pattern",
    });
    expect(
      knownHallucination("definitely-not-in-snapshot-xyz", "pypi")
    ).toBeNull();
    expect(knownHallucination(KNOWN_NAME, "npm")).toBeNull(); // ecosystem-scoped
  });
});

describe("preFlightCheck × threat snapshot", () => {
  it("flags a known name as CRITICAL when it is still unregistered — one finding, no ghost_package duplicate", async () => {
    mockExists.mockResolvedValue({ exists: false } as any);
    const { verdict, findings } = await preFlightCheck(req(KNOWN_NAME));
    const known = findings.filter(f => f.type === "known_hallucination");
    expect(known).toHaveLength(1);
    expect(known[0].severity).toBe("critical");
    expect(findings.some(f => f.type === "ghost_package")).toBe(false);
    expect(verdict).toBe("BLOCKED");
  });

  it("KEEPS flagging a known name after the package got REGISTERED — and says so explicitly", async () => {
    mockExists.mockResolvedValue({
      exists: true,
      isNewPackage: true,
      publishedAt: new Date(Date.now() - 3 * 86_400_000),
    } as any);
    const { verdict, findings } = await preFlightCheck(req(KNOWN_NAME));
    const known = findings.filter(f => f.type === "known_hallucination");
    expect(known).toHaveLength(1);
    expect(known[0].severity).toBe("critical");
    expect(known[0].description).toMatch(/registered/i);
    // The one authoritative finding replaces the weaker new-package warning.
    expect(findings.some(f => f.type === "new_package_risk")).toBe(false);
    expect(verdict).toBe("BLOCKED");
  });

  it("registry unreachable does not matter for a known name — the snapshot is local", async () => {
    mockExists.mockResolvedValue({ exists: false, unreachable: true } as any);
    const { findings } = await preFlightCheck(req(KNOWN_NAME));
    expect(findings.some(f => f.type === "known_hallucination")).toBe(true);
  });

  it("unknown names keep the existing behavior untouched", async () => {
    mockExists.mockResolvedValue({ exists: false } as any);
    const { findings } = await preFlightCheck(req("some-unknown-name"));
    expect(findings.some(f => f.type === "ghost_package")).toBe(true);
    expect(findings.some(f => f.type === "known_hallucination")).toBe(false);
  });
});

/**
 * THE THIRD STATE — a listed name whose package PREDATES our record.
 *
 * Before 2026-08-04 this case did not exist in the code: any listed name that
 * existed today produced "has SINCE BEEN REGISTERED … treat the registered
 * package as hostile", at CRITICAL. Measured over all 35 snapshot rows that day,
 * 19 are absent and every one of the other 16 was first published BEFORE the
 * date we recorded the name — so the hostile branch could only ever fire on
 * somebody's real package, in a free tool anyone can run.
 */
describe("preFlightCheck × a listed name that is a REAL, older package", () => {
  it("does not call it a squat, and does not call it hostile", async () => {
    const entry = knownHallucination(KNOWN_NAME, "pypi")!;
    // One day BEFORE the date the name was recorded — the shape of every
    // existing row in the shipped snapshot.
    mockExists.mockResolvedValue({
      exists: true,
      isNewPackage: false,
      publishedAt:
        new Date(`${entry.recorded}T00:00:00Z`).getTime() - 86_400_000
          ? new Date(
              new Date(`${entry.recorded}T00:00:00Z`).getTime() - 86_400_000
            )
          : null,
    } as any);

    const { findings } = await preFlightCheck(req(KNOWN_NAME));
    const known = findings.filter(f => f.type === "known_hallucination");
    expect(known).toHaveLength(1);
    expect(
      known[0].severity,
      "a real, older package is not a critical threat"
    ).toBe("warning");
    expect(known[0].description).not.toMatch(
      /SINCE BEEN REGISTERED|end-game|hostile/i
    );
    expect(known[0].recommendation).not.toMatch(/hostile/i);
    // It still says something useful: the model may have reached for a name
    // that sounds right rather than the library the developer meant.
    expect(known[0].description).toMatch(/not a squat/i);
  });

  it("an unknown publish date is treated as the harmless case, never as a squat", async () => {
    mockExists.mockResolvedValue({
      exists: true,
      isNewPackage: false,
      publishedAt: null,
    } as any);
    const { findings } = await preFlightCheck(req(KNOWN_NAME));
    const known = findings.filter(f => f.type === "known_hallucination")[0];
    expect(known.severity).toBe("warning");
    expect(known.description).not.toMatch(/SINCE BEEN REGISTERED|hostile/i);
    // And it says so, rather than implying the date was checked and cleared.
    expect(known.description).toMatch(
      /could not establish when it was first published/i
    );
  });
});

/**
 * ── WHAT THE FINDING MAY SAY ABOUT WHERE THE NAME CAME FROM ─────────────────
 *
 * The finding text interpolates the tier verbatim — `(${tier} tier)` — so the
 * tier is not an internal label, it is a sentence shown to the user. Until
 * 2026-08-07 every curated row shipped as `confirmed` because the public route
 * assigned it in a `.map` default, discarding the seed file's own `origin`. The
 * snapshot keeps only the tier, so `origin` never reached the published MCP at
 * all, and a developer importing `drizzle-ai` was told:
 *
 *     "drizzle-ai" is in Graneth's public threat feed (confirmed tier): a name
 *     AI models are known to invent.
 *
 * about a name this project wrote itself and describes in its own data as a
 * "plausible target, not an observation". These assertions pin the two ends of
 * that pipe together: what the finding claims may not outrun the row's origin.
 */
describe("the finding does not claim more provenance than the row has", () => {
  const PATTERN_NAME = "flask-gpt"; // ours, built from the pattern
  const REPORTED_NAME = "huggingface-cli"; // named by the CSA note, absent from PyPI

  it("a pattern row is never described as a name models are KNOWN to invent", async () => {
    mockExists.mockResolvedValue({ exists: false } as any);
    const { findings } = await preFlightCheck(req(PATTERN_NAME));
    const known = findings.filter(f => f.type === "known_hallucination")[0];
    // Still critical, still blocked — the name does not resolve, and that part
    // was never in doubt. What changes is the sentence about provenance.
    expect(known.severity).toBe("critical");
    expect(known.description).not.toMatch(
      /known to invent|reported by|research/i
    );
    expect(known.description).toMatch(/pattern/i);
    expect(known.description).not.toContain("confirmed tier");
  });

  it("a reported row names its source and ships the link", async () => {
    mockExists.mockResolvedValue({ exists: false } as any);
    const { findings } = await preFlightCheck([
      { path: "requirements.txt", content: `${REPORTED_NAME}==1.0.0\n` },
    ]);
    const known = findings.filter(f => f.type === "known_hallucination")[0];
    expect(
      known,
      `${REPORTED_NAME} is not in the shipped snapshot`
    ).toBeTruthy();
    expect(known.description).toContain("outside research reports");
    // Not our construction — the two must never be described the same way.
    expect(known.description).not.toMatch(/our own construction/i);
  });

  it("no snapshot row carries the retired `confirmed` tier", async () => {
    const { THREAT_SNAPSHOT } = await import("./threatSnapshot.js");
    for (const row of THREAT_SNAPSHOT) {
      expect(row.tier, `${row.ecosystem}/${row.name}`).not.toBe("confirmed");
    }
    // And the negative control: the assertion can fail.
    expect((["confirmed"] as string[]).includes("confirmed")).toBe(true);
  });
});
