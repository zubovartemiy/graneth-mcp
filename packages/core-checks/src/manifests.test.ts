/**
 * Manifest dependency extraction — package.json + requirements.txt.
 *
 * Dogfood 2026-07-10 found the gap this pins: the tool description promises
 * manifest checking, but only import statements were parsed — a hallucinated
 * dependency added straight to package.json / requirements.txt (the most
 * common way AI agents add deps) sailed through as CLEAR.
 */
import { describe, it, expect } from "vitest";
import { extractManifestPackages } from "./manifests.js";

function extract(path: string, content: string) {
  return extractManifestPackages([{ path, content }]);
}

describe("package.json extraction", () => {
  const manifest = [
    "{",
    '  "name": "app",',
    '  "dependencies": {',
    '    "left-pad": "^1.3.0",',
    '    "@scope/thing": "2.0.0",',
    '    "local-lib": "file:../local-lib",',
    '    "ws-lib": "workspace:*",',
    '    "cat-lib": "catalog:",',
    '    "gh-lib": "github:user/repo",',
    '    "short-gh": "user/repo",',
    '    "git-lib": "git+https://github.com/u/r.git",',
    '    "url-lib": "https://example.com/x.tgz",',
    '    "aliased": "npm:real-target@^1.0.0",',
    '    "scoped-alias": "npm:@scope/real@2"',
    "  },",
    '  "devDependencies": { "dev-tool": "1.0.0" },',
    '  "peerDependencies": { "peer-lib": ">=1" },',
    '  "optionalDependencies": { "opt-lib": "*" }',
    "}",
  ].join("\n");

  it("collects registry deps from all four dependency sections", () => {
    const { refs, errors } = extract("package.json", manifest);
    expect(errors).toEqual([]);
    const names = refs.map((r) => r.pkg).sort();
    expect(names).toEqual(
      ["@scope/real", "@scope/thing", "dev-tool", "left-pad", "opt-lib", "peer-lib", "real-target"].sort(),
    );
    for (const r of refs) expect(r.ecosystem).toBe("npm");
  });

  it("reports the manifest line the dependency is declared on", () => {
    const { refs } = extract("package.json", manifest);
    expect(refs.find((r) => r.pkg === "left-pad")).toMatchObject({ filename: "package.json", line: 4 });
    expect(refs.find((r) => r.pkg === "dev-tool")).toMatchObject({ line: 16 });
  });

  it("never sends workspace/file/link/git/github/catalog/URL specifiers to the registry", () => {
    const { refs } = extract("package.json", manifest);
    const names = refs.map((r) => r.pkg);
    for (const skipped of ["local-lib", "ws-lib", "cat-lib", "gh-lib", "short-gh", "git-lib", "url-lib"]) {
      expect(names).not.toContain(skipped);
    }
  });

  it("resolves npm: aliases to the real registry target, not the local alias name", () => {
    const { refs } = extract("package.json", manifest);
    expect(refs.map((r) => r.pkg)).toContain("real-target");
    expect(refs.map((r) => r.pkg)).toContain("@scope/real");
    expect(refs.map((r) => r.pkg)).not.toContain("aliased");
    expect(refs.map((r) => r.pkg)).not.toContain("scoped-alias");
  });

  it("reports a parse error for malformed JSON instead of returning silent-clean", () => {
    const { refs, errors } = extract("package.json", '{ "dependencies": { oops');
    expect(refs).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0].file).toBe("package.json");
    expect(errors[0].message.length).toBeGreaterThan(0);
  });

  it("matches nested manifests but not lockfiles or other JSON", () => {
    expect(extract("backend/package.json", manifest).refs.length).toBeGreaterThan(0);
    expect(extract("package-lock.json", manifest).refs).toEqual([]);
    expect(extract("tsconfig.json", manifest).refs).toEqual([]);
  });

  it("tolerates a manifest with no dependency sections", () => {
    const { refs, errors } = extract("package.json", '{ "name": "x", "version": "1.0.0" }');
    expect(refs).toEqual([]);
    expect(errors).toEqual([]);
  });
});

describe("requirements.txt extraction", () => {
  const reqs = [
    "# base deps",
    "requests==2.32.0",
    "Flask_Login>=0.6   # session handling",
    "uvicorn[standard]~=0.30",
    'Django ; python_version >= "3.10"',
    "torch.audio==2.0",
    "-r base.txt",
    "--hash=sha256:deadbeef",
    "-e .",
    "./local-pkg",
    "https://files.pythonhosted.org/x.whl",
    "mypkg @ https://example.com/mypkg.whl",
    "",
  ].join("\n");

  it("parses names, strips versions/extras/markers, normalizes _ and . to -", () => {
    const { refs, errors } = extract("requirements.txt", reqs);
    expect(errors).toEqual([]);
    expect(refs.map((r) => r.pkg).sort()).toEqual(
      ["Django", "Flask-Login", "requests", "torch-audio", "uvicorn"].sort(),
    );
    for (const r of refs) expect(r.ecosystem).toBe("pypi");
    expect(refs.find((r) => r.pkg === "requests")).toMatchObject({ filename: "requirements.txt", line: 2 });
    expect(refs.find((r) => r.pkg === "Flask-Login")).toMatchObject({ line: 3 });
  });

  it("skips comments, blanks, option lines, URLs, local paths and direct references", () => {
    const { refs } = extract("requirements.txt", reqs);
    expect(refs.map((r) => r.pkg)).not.toContain("mypkg");
    expect(refs).toHaveLength(5);
  });

  it("matches requirements variants and nested paths", () => {
    expect(extract("requirements-dev.txt", "pytest==8.0").refs).toHaveLength(1);
    expect(extract("dev-requirements.txt", "pytest==8.0").refs).toHaveLength(1);
    expect(extract("backend/requirements.txt", "pytest==8.0").refs).toHaveLength(1);
    expect(extract("notes.txt", "pytest==8.0").refs).toEqual([]);
  });
});

describe("cross-file behavior", () => {
  it("dedupes the same package across manifests (first seen wins)", () => {
    const { refs } = extractManifestPackages([
      { path: "package.json", content: '{ "dependencies": { "left-pad": "^1.0.0" } }' },
      { path: "backend/package.json", content: '{ "dependencies": { "left-pad": "^1.0.0" } }' },
    ]);
    expect(refs).toHaveLength(1);
    expect(refs[0].filename).toBe("package.json");
  });

  it("ignores non-manifest files entirely", () => {
    const { refs, errors } = extractManifestPackages([
      { path: "src/app.ts", content: 'import x from "not-a-manifest";' },
    ]);
    expect(refs).toEqual([]);
    expect(errors).toEqual([]);
  });
});
