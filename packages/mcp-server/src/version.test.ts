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
import path from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = path.resolve(fileURLToPath(import.meta.url), "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(PKG_DIR, rel), "utf8");

const manifestVersion = (): string => JSON.parse(read("package.json")).version;

/** The literal the server answers `initialize` with. */
const reportedVersion = (): string => {
  const src = read("src/index.ts");
  const m = /const VERSION = "([^"]+)"/.exec(src);
  if (!m) throw new Error("src/index.ts no longer declares `const VERSION = \"…\"` — update this guard, do not delete it");
  return m[1];
};

/** Both places the registry manifest states a version. */
const registryVersions = (): string[] => {
  const doc = JSON.parse(read("server.json")) as { version: string; packages: Array<{ version: string }> };
  return [doc.version, ...doc.packages.map((p) => p.version)];
};

describe("every place that states this package's version agrees", () => {
  it("the server reports the version npm installed", () => {
    expect(
      reportedVersion(),
      "a client would be told a version different from the one it installed",
    ).toBe(manifestVersion());
  });

  it("the registry manifest states the same version, in every field", () => {
    for (const v of registryVersions()) {
      expect(v, "server.json describes a different release than package.json — and it is PUBLIC").toBe(
        manifestVersion(),
      );
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
  const SKIP = new Set(["node_modules", ".git", "dist", "dist-public", "build", "coverage", ".next", "test-results", "playwright-report"]);

  const manifests: string[] = [];
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) walk(path.join(dir, e.name));
        continue;
      }
      if (e.name !== "server.json") continue;
      const full = path.join(dir, e.name);
      let doc: unknown;
      try {
        doc = JSON.parse(fs.readFileSync(full, "utf8"));
      } catch {
        continue; // not parseable — not a manifest claim
      }
      // Identified by what it IS, not by where it sits: any file naming the MCP
      // registry schema is a manifest, wherever somebody puts it.
      const schema = (doc as { $schema?: unknown }).$schema;
      if (typeof schema === "string" && schema.includes("modelcontextprotocol.io")) {
        manifests.push(path.relative(REPO_ROOT, full).split(path.sep).join("/"));
      }
    }
  };
  walk(REPO_ROOT);

  it("finds it, and finds only it", () => {
    expect(
      manifests.sort(),
      "more than one file claims the MCP registry schema. The registry takes ONE document; " +
        "a second copy is the one that goes stale, and last time it was the second copy that " +
        "was actually published while the guarded one sat a minor version behind.",
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
