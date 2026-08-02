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
