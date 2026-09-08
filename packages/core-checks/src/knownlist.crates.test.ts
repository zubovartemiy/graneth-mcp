/**
 * crates.io TREATS `_` AND `-` AS THE SAME CRATE, AND SO MUST THE LOCAL LIST.
 *
 * The registry client says so in its own comment; the index did not. It keyed
 * on the exact string, so a name reported as `foo-gpt` never matched
 * `use foo_gpt;` — and the local list, whose entire purpose is to keep catching
 * a name after an attacker registers it, quietly did not.
 *
 * ── WHY THE SNAPSHOT IS MOCKED HERE ─────────────────────────────────────────
 * The bundled snapshot today holds only npm and PyPI names, so a test written
 * against the real data would SKIP — and a skipped test reports nothing while
 * looking like coverage. The first version of this file did exactly that: it
 * was `it.runIf(...)`, it never ran, and reverting the fix did not redden it.
 * Substituting the data is what makes the assertion possible before the first
 * crates row exists, which is the point of fixing it now.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("./threatSnapshot.js", () => ({
  THREAT_SNAPSHOT: [
    {
      name: "serde-gpt",
      ecosystem: "crates",
      tier: "pattern",
      recorded: "2026-01-01",
    },
    {
      name: "express-gpt",
      ecosystem: "npm",
      tier: "pattern",
      recorded: "2026-01-01",
    },
  ],
}));

const { knownHallucination } = await import("./knownHallucinations.js");

describe("crates spellings the registry considers identical", () => {
  it("matches the underscore spelling of a listed crate", () => {
    expect(knownHallucination("serde_gpt", "crates")).not.toBeNull();
  });

  it("matches the spelling as listed", () => {
    expect(knownHallucination("serde-gpt", "crates")).not.toBeNull();
  });

  it("matches regardless of case, as crates.io does", () => {
    expect(knownHallucination("Serde_GPT", "crates")).not.toBeNull();
  });

  it("does NOT fold underscores for npm", () => {
    // npm and PyPI treat the two spellings as different names, and folding
    // there would match a package nobody listed — a false accusation.
    expect(knownHallucination("express_gpt", "npm")).toBeNull();
    expect(knownHallucination("express-gpt", "npm")).not.toBeNull();
  });

  it("still returns null for a name on no list", () => {
    expect(knownHallucination("zzz-not-listed", "crates")).toBeNull();
  });
});
