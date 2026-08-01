/**
 * Evidence-based internal-name resolution (issue #152, core path).
 *
 * A syntactically valid scoped import that 404s on npm is EITHER a
 * hallucination (a real benchmark attack shape) OR a workspace/tsconfig-alias
 * name. The difference is evidence: when the scanned payload itself contains
 * a tsconfig path mapping or a workspace manifest declaring the name, the
 * import is internal and must not produce a ghost critical. Without evidence
 * the detector keeps failing toward detection.
 */
import { describe, it, expect } from "vitest";
import { extractInternalNameEvidence, isInternalName } from "./internalNames.js";

const tsconfig = JSON.stringify({
  compilerOptions: {
    paths: {
      "@/*": ["./client/src/*"],
      "@shared/*": ["./shared/*"],
      "@graneth/core-checks": ["./packages/core-checks/src/index.ts"],
    },
  },
});

describe("extractInternalNameEvidence", () => {
  it("collects exact names and prefix patterns from tsconfig paths", () => {
    const ev = extractInternalNameEvidence([{ path: "tsconfig.json", content: tsconfig }]);
    expect(isInternalName("@graneth/core-checks", ev)).toBe(true);
    expect(isInternalName("@shared/const", ev)).toBe(true);
    expect(isInternalName("@shared/anything", ev)).toBe(true);
    expect(isInternalName("left-pad", ev)).toBe(false);
    expect(isInternalName("@scope/other", ev)).toBe(false);
  });

  it("collects workspace manifest names and workspace-protocol dependencies", () => {
    const ev = extractInternalNameEvidence([
      { path: "packages/core-checks/package.json", content: '{ "name": "@graneth/core-checks", "private": true }' },
      { path: "package.json", content: '{ "name": "app", "dependencies": { "ui-kit": "workspace:*", "real-dep": "^1.0.0" } }' },
    ]);
    expect(isInternalName("@graneth/core-checks", ev)).toBe(true);
    expect(isInternalName("ui-kit", ev)).toBe(true);
    expect(isInternalName("real-dep", ev)).toBe(false); // registry dep, NOT internal
  });

  it("tolerates jsonc comments in tsconfig and yields no evidence on a hopeless parse", () => {
    const jsonc = `{
      // path aliases
      "compilerOptions": { "paths": { "@app/*": ["./src/*"] /* alias */ } }
    }`;
    const ev = extractInternalNameEvidence([{ path: "tsconfig.json", content: jsonc }]);
    expect(isInternalName("@app/thing", ev)).toBe(true);

    const broken = extractInternalNameEvidence([{ path: "tsconfig.json", content: "{ not json at all" }]);
    expect(isInternalName("@app/thing", broken)).toBe(false); // no evidence → keep detection
  });

  it("matches tsconfig variants (tsconfig.base.json) but not arbitrary json", () => {
    const ev = extractInternalNameEvidence([{ path: "tsconfig.base.json", content: tsconfig }]);
    expect(isInternalName("@shared/const", ev)).toBe(true);
    const none = extractInternalNameEvidence([{ path: "config.json", content: tsconfig }]);
    expect(isInternalName("@shared/const", none)).toBe(false);
  });
});
