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

vi.mock("./registry.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("./registry.js")>();
  return { ...orig, packageExists: vi.fn(orig.packageExists) };
});

import { preFlightCheck } from "./preflight.js";
import { packageExists } from "./registry.js";
import { knownHallucination } from "./knownHallucinations.js";

const mockExists = vi.mocked(packageExists);

beforeEach(() => vi.clearAllMocks());
afterEach(() => vi.restoreAllMocks());

const req = (name: string) => [{ path: "requirements.txt", content: `${name}==1.0.0\n` }];

describe("knownHallucination lookup", () => {
  it("finds a snapshot entry with its tier and misses unknown names", () => {
    expect(knownHallucination(KNOWN_NAME, "pypi")).toMatchObject({ tier: "confirmed" });
    expect(knownHallucination("definitely-not-in-snapshot-xyz", "pypi")).toBeNull();
    expect(knownHallucination(KNOWN_NAME, "npm")).toBeNull(); // ecosystem-scoped
  });
});

describe("preFlightCheck × threat snapshot", () => {
  it("flags a known name as CRITICAL when it is still unregistered — one finding, no ghost_package duplicate", async () => {
    mockExists.mockResolvedValue({ exists: false } as any);
    const { verdict, findings } = await preFlightCheck(req(KNOWN_NAME));
    const known = findings.filter((f) => f.type === "known_hallucination");
    expect(known).toHaveLength(1);
    expect(known[0].severity).toBe("critical");
    expect(findings.some((f) => f.type === "ghost_package")).toBe(false);
    expect(verdict).toBe("BLOCKED");
  });

  it("KEEPS flagging a known name after the package got REGISTERED — and says so explicitly", async () => {
    mockExists.mockResolvedValue({
      exists: true,
      isNewPackage: true,
      publishedAt: new Date(Date.now() - 3 * 86_400_000),
    } as any);
    const { verdict, findings } = await preFlightCheck(req(KNOWN_NAME));
    const known = findings.filter((f) => f.type === "known_hallucination");
    expect(known).toHaveLength(1);
    expect(known[0].severity).toBe("critical");
    expect(known[0].description).toMatch(/registered/i);
    // The one authoritative finding replaces the weaker new-package warning.
    expect(findings.some((f) => f.type === "new_package_risk")).toBe(false);
    expect(verdict).toBe("BLOCKED");
  });

  it("registry unreachable does not matter for a known name — the snapshot is local", async () => {
    mockExists.mockResolvedValue({ exists: false, unreachable: true } as any);
    const { findings } = await preFlightCheck(req(KNOWN_NAME));
    expect(findings.some((f) => f.type === "known_hallucination")).toBe(true);
  });

  it("unknown names keep the existing behavior untouched", async () => {
    mockExists.mockResolvedValue({ exists: false } as any);
    const { findings } = await preFlightCheck(req("some-unknown-name"));
    expect(findings.some((f) => f.type === "ghost_package")).toBe(true);
    expect(findings.some((f) => f.type === "known_hallucination")).toBe(false);
  });
});
