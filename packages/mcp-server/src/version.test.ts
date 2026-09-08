/**
 * ONE VERSION, THREE PLACES THAT STATE IT — and they had already drifted.
 *
 * The number lives in three files, each read by a different audience:
 *
 *   package.json          what npm installs
 *   src/index.ts VERSION  what the server reports over MCP on `initialize`
 *   server.json           what the MCP registry manifest claims, and it ships
 *                         in the PUBLIC mirror
 *
 * Measured on 2026-08-02, before the 0.7.1 bump: `package.json` and `index.ts`
 * said 0.7.0 while `server.json` said 0.6.0 — in two fields — so a public file
 * described a package one minor behind the one on the registry, and nothing
 * reddened. A release bump touched the first two by hand and the third not at
 * all, which is the whole failure: a fact with three homes has no home.
 *
 * This cannot be fixed by "remember to update all three" — server.json is a
 * static document the registry consumes, and index.ts must not read a manifest
 * at runtime (the package is deliberately dependency-free and bundled). So the
 * duplication stays and the AGREEMENT is enforced here instead.
 */
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = path.resolve(fileURLToPath(import.meta.url), "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(PKG_DIR, rel), "utf8");

const manifestVersion = (): string => JSON.parse(read("package.json")).version;

/** The literal the server answers `initialize` with. */
const reportedVersion = (): string => {
  const src = read("src/index.ts");
  const m = /const VERSION = "([^"]+)"/.exec(src);
  if (!m)
    throw new Error(
      'src/index.ts no longer declares `const VERSION = "…"` — update this guard, do not delete it'
    );
  return m[1];
};

/** Both places the registry manifest states a version. */
const registryVersions = (): string[] => {
  const doc = JSON.parse(read("server.json")) as {
    version: string;
    packages: Array<{ version: string }>;
  };
  return [doc.version, ...doc.packages.map(p => p.version)];
};

describe("every place that states this package's version agrees", () => {
  it("the server reports the version npm installed", () => {
    expect(
      reportedVersion(),
      "a client would be told a version different from the one it installed"
    ).toBe(manifestVersion());
  });

  it("the registry manifest states the same version, in every field", () => {
    for (const v of registryVersions()) {
      expect(
        v,
        "server.json describes a different release than package.json — and it is PUBLIC"
      ).toBe(manifestVersion());
    }
  });

  it("the version is a plain semver triple", () => {
    // Guards against a bump that lands as "0.7.1 " or "v0.7.1" in one file only.
    expect(manifestVersion()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

/**
 * ── AND THE FOURTH PLACE, WHICH THIS GUARD COULD NOT SEE ────────────────────
 *
 * The block above pins three files INSIDE this package. On 2026-08-07 a second
 * registry manifest was found at `distribution-drafts/server.json`, outside the
 * denominator, and `distribution-drafts/INDEX.md` instructed the reader to set
 * the version in THAT one.
 *
 * It was not a stale copy of the package manifest — it was the PUBLISHED one.
 * Measured against `registry.modelcontextprotocol.io`: the live `0.7.1` entry
 * carries `title: "Graneth"`, a `repository` block and `registryBaseUrl`,
 * fields that existed only in the draft. So the guard was pinning three files a
 * human never publishes while the document that actually reaches the registry
 * was versioned by nothing at all — the same shape as a lint scope that walks
 * the wrong tree, one directory over.
 *
 * The draft is deleted and its fields merged here. This test is the obligation
 * that keeps it deleted: a prohibition in prose ("don't make a second copy") is
 * the half of a guard nothing checks.
 */
describe("there is exactly one MCP registry manifest in this repository", () => {
  const REPO_ROOT = path.resolve(PKG_DIR, "..", "..");
  // Generated and tool-owned directories. `.stryker-tmp` earns its place the
  // hard way: Stryker copies the whole repository into a sandbox there while it
  // runs, so this suite found a SECOND server.json and failed — correctly by its
  // own rule, and about nothing. A guard that passes or fails depending on
  // whether another tool happens to be running at the same moment is worse than
  // no guard, because the false alarm is indistinguishable from the real one it
  // exists to raise.

  /**
   * TRACKED FILES ONLY.
   *
   * This walked the disk, so a gitignored directory could fail it — and one did:
   * a leftover `git worktree` under `.claude/worktrees/` held a second copy of
   * the manifest and turned this guard red over a file that is not part of the
   * repository at all. The question it exists to ask is "does the REPOSITORY
   * ship two manifests", and `git ls-files` is what answers that. The same
   * correction publishedIdentity.test.ts needed, for the same reason: enumerate
   * the right set, or the check reports on something nobody asked about.
   */
  const manifests: string[] = execFileSync(
    "git",
    ["ls-files", "*server.json"],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
    }
  )
    .split(/\r?\n/)
    .filter(Boolean)
    .filter(rel => {
      let doc: unknown;
      try {
        doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"));
      } catch {
        return false; // not parseable — not a manifest claim
      }
      // Identified by what it IS, not by where it sits: any file naming the MCP
      // registry schema is a manifest, wherever somebody puts it.
      const schema = (doc as { $schema?: unknown }).$schema;
      return (
        typeof schema === "string" && schema.includes("modelcontextprotocol.io")
      );
    });

  it("finds it, and finds only it", () => {
    expect(
      manifests.sort(),
      "more than one file claims the MCP registry schema. The registry takes ONE document; " +
        "a second copy is the one that goes stale, and last time it was the second copy that " +
        "was actually published while the guarded one sat a minor version behind."
    ).toEqual(["packages/mcp-server/server.json"]);
  });

  it("the walk actually reaches files — the assertion is not vacuous", () => {
    // A traversal that silently found nothing would pass the test above by
    // returning [] against a one-element expectation… which fails. But a bug
    // that skipped the package dir AND relaxed the expectation would not, so
    // the reach is asserted on its own.
    expect(fs.existsSync(path.join(PKG_DIR, "server.json"))).toBe(true);
    expect(manifests.length).toBeGreaterThan(0);
  });
});
