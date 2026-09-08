/**
 * When may a 404 from the registry BLOCK a commit?
 *
 * ── THE MEASUREMENT THAT FORCED THE QUESTION ────────────────────────────────
 * The product rule requires a published false-positive rate per blocking category before
 * anything is sold, and none existed. The first one ran `preFlightCheck` over
 * this repository's own history — 154 commits, 1,446 file versions, 21 MB of
 * code that was written, reviewed, merged and is still running. A finding on
 * that corpus is a candidate false positive by default.
 *
 * It produced **76 production-path criticals, and every one was wrong**:
 * `@shared/const`, `@shared/buildProvenance`, `@graneth/core-checks` — path
 * aliases and workspace packages, reported as "the hallmark of an
 * AI-hallucinated dependency" and blocking the commit that touched them.
 *
 * The cause is not a broken guard. `isInternalName` is correct and STARVED: it
 * resolves a name against `tsconfig.json` paths and workspace manifests, and
 * the published tool's own contract is "files staged for commit", which almost
 * never includes them.
 *
 * ── TWO WRONG FIXES, AND WHAT THE TREE SAID ABOUT THEM ──────────────────────
 * The first attempt extended `scanSecrets`'s test-path downgrade to package
 * findings, because 92 further criticals sat on test files. `preflight.test.ts`
 * refused it — "still BLOCKS ghost packages even in test files" — and it was
 * right for a reason the measurement did not contain: a secret in a test file
 * is inert data, and an imported package in a test file is a REAL DEPENDENCY
 * that the package manager installs and whose install scripts run. Reverted.
 *
 * The second attempt blocked only on manifest-declared names. That killed the
 * false positives and also killed the product: an agent writes
 * `import x from "hallucinated-pkg"` and installs it a moment later, and
 * catching the import BEFORE the install is the entire point of a pre-flight
 * check.
 *
 * ── THE DISCRIMINATOR THE DATA ACTUALLY CONTAINED ───────────────────────────
 * All 76 false criticals carried a SCOPE. Every fixture name that should still
 * block — `malware-pkg`, `reqeusts`, `ghost-pkg` — did not. Path aliases and
 * monorepo packages use invented scopes because a scope is cheap and
 * unregistered; a bare name is not a tsconfig alias, so npm's 404 on it means
 * what it says.
 *
 * A 404 therefore blocks when any of three holds: the name is DECLARED in a
 * manifest, the diff carried the evidence and `isInternalName` still said no,
 * or the name is UNSCOPED. Otherwise it is reported by name, with what to
 * include to get a definitive answer.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const { packageExistsMock } = vi.hoisted(() => ({
  packageExistsMock: vi.fn(),
}));

vi.mock("./registry.js", () => ({
  packageExists: packageExistsMock,
}));

import { preFlightCheck } from "./preflight.js";

beforeEach(() => {
  vi.clearAllMocks();
  // Nothing exists, so every reference is a miss and SEVERITY is what is under
  // test rather than the lookup.
  packageExistsMock.mockResolvedValue({ exists: false });
});

const ghostsIn = async (files: { path: string; content: string }[]) =>
  (await preFlightCheck(files)).findings.filter(
    f => f.type === "ghost_package"
  );

describe("a scoped miss with no evidence is reported, not blocked", () => {
  it("does not block on a path alias the diff cannot resolve", async () => {
    const ghosts = await ghostsIn([
      {
        path: "server/app/index.ts",
        content: `import { ENV } from "@shared/const";\n`,
      },
    ]);

    expect(ghosts.length).toBeGreaterThan(0);
    expect(
      ghosts.every(f => f.severity !== "critical"),
      "76 of these blocked legitimate commits over this repository's own history"
    ).toBe(true);
  });

  it("names the package and says what would settle it", async () => {
    // Reported, never dropped. A finding the reader cannot act on is the same
    // failure one step later.
    const [ghost] = await ghostsIn([
      { path: "src/a.ts", content: `import x from "@acme/thing";\n` },
    ]);
    expect(ghost.title).toContain("@acme/thing");
    expect(ghost.description.toLowerCase()).toContain("tsconfig");
  });

  it("DOES block once the diff carries evidence about that same scope", async () => {
    // The tsconfig shows `@acme` IS an alias scope here and lists what is in
    // it. `@acme/thing` is not, so `isInternalName` ran with the right facts
    // and said no. That is an answer, and it may block.
    const ghosts = await ghostsIn([
      {
        path: "tsconfig.json",
        content: JSON.stringify({
          compilerOptions: { paths: { "@acme/known/*": ["./src/known/*"] } },
        }),
      },
      { path: "src/a.ts", content: `import x from "@acme/thing";\n` },
    ]);
    expect(ghosts.some(f => f.severity === "critical")).toBe(true);
  });

  it("is not satisfied by a manifest from an unrelated scope", async () => {
    // The first version of this rule asked only "was any manifest present".
    // Four production criticals survived it, in commits that happened to touch
    // `packages/mcp-server/package.json` — a file that says nothing whatever
    // about `@shared`. Presence of some evidence is not evidence.
    const ghosts = await ghostsIn([
      {
        path: "packages/other/package.json",
        content: JSON.stringify({ name: "@other/thing", dependencies: {} }),
      },
      { path: "src/a.ts", content: `import x from "@shared/const";\n` },
    ]);
    expect(ghosts.length).toBeGreaterThan(0);
    expect(ghosts.every(f => f.severity !== "critical")).toBe(true);
  });
});

describe("an unscoped miss still blocks, because it means what it says", () => {
  it("blocks a bare hallucinated import with no evidence present", async () => {
    // The pre-flight case the product exists for: the import precedes the
    // install, and this is the moment to catch it.
    const ghosts = await ghostsIn([
      { path: "src/a.ts", content: `import x from "hallucinated-pkg";\n` },
    ]);
    expect(ghosts.some(f => f.severity === "critical")).toBe(true);
  });

  it("blocks it in a test file too", async () => {
    // Deliberate, and older than this file: an imported package in a test file
    // is a real dependency, unlike a secret in a test file, which is fake data.
    const ghosts = await ghostsIn([
      { path: "src/app.test.ts", content: `import g from "ghost-pkg";\n` },
    ]);
    expect(ghosts.some(f => f.severity === "critical")).toBe(true);
  });
});

describe("a declared dependency blocks whatever its shape", () => {
  it("blocks a scoped name written into a manifest", async () => {
    // Somebody wrote it down as a dependency and the registry does not have
    // it. Scope or no scope, that is demonstrable.
    const ghosts = await ghostsIn([
      {
        path: "package.json",
        content: JSON.stringify({
          name: "app",
          dependencies: { "@acme/not-real": "^1.0.0" },
        }),
      },
    ]);
    expect(ghosts.some(f => f.severity === "critical")).toBe(true);
  });
});
