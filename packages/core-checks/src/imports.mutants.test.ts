/**
 * Mutation-driven coverage for imports.ts — pins every import-extraction
 * regex the first Stryker run showed surviving mutants in: ESM/dynamic/
 * re-export/CJS forms, the relative-path guard, scoped-name rooting, python
 * forms with the underscore→dash normalization, and extension routing.
 */
import { describe, it, expect } from "vitest";
import { primaryEcosystem, extractImportedPackages } from "./imports.js";

function refs(path: string, content: string) {
  return extractImportedPackages([{ path, content }]);
}

describe("primaryEcosystem", () => {
  it("routes python and JS/TS extensions case-insensitively, null otherwise", () => {
    expect(primaryEcosystem("a.py")).toBe("pypi");
    expect(primaryEcosystem("a.pyw")).toBe("pypi");
    expect(primaryEcosystem("a.pyi")).toBe("pypi");
    expect(primaryEcosystem("A.PY")).toBe("pypi");
    for (const ext of ["js", "jsx", "ts", "tsx", "mjs", "cjs"]) expect(primaryEcosystem(`a.${ext}`)).toBe("npm");
    expect(primaryEcosystem("a.rb")).toBeNull();
    expect(primaryEcosystem("Dockerfile")).toBeNull();
    expect(primaryEcosystem("test.pyc")).toBeNull(); // compiled, not source
  });
});

describe("JS/TS extraction forms", () => {
  it("static ESM with and without bindings", () => {
    expect(refs("a.ts", `import axios from "axios";`)[0]).toMatchObject({ pkg: "axios", line: 1 });
    expect(refs("a.ts", `import "polyfill-lib";`)[0]).toMatchObject({ pkg: "polyfill-lib" });
    expect(refs("a.ts", `import { x, y } from 'some-lib'`)[0]).toMatchObject({ pkg: "some-lib" });
  });

  it("dynamic import() incl. await and spacing", () => {
    expect(refs("a.ts", `const m = await import( 'lazy-lib' );`)[0]).toMatchObject({ pkg: "lazy-lib" });
    // Space BETWEEN the keyword and the paren — kills the \s*→\S* regex mutants.
    expect(refs("a.ts", `const m = await import ('spaced-dyn-lib');`)[0]).toMatchObject({ pkg: "spaced-dyn-lib" });
    expect(refs("a.cjs", `const x = require ('spaced-cjs-lib');`)[0]).toMatchObject({ pkg: "spaced-cjs-lib" });
  });

  it("re-exports (barrel files)", () => {
    expect(refs("a.ts", `export { thing } from "barrel-lib";`)[0]).toMatchObject({ pkg: "barrel-lib" });
    expect(refs("a.ts", `export * from "star-lib";`)[0]).toMatchObject({ pkg: "star-lib" });
  });

  it("CommonJS require", () => {
    expect(refs("a.cjs", `const x = require("cjs-lib");`)[0]).toMatchObject({ pkg: "cjs-lib" });
    expect(refs("a.cjs", `require( 'spaced-lib' )`)[0]).toMatchObject({ pkg: "spaced-lib" });
  });

  it("roots deep paths and keeps the @scope/name pair intact", () => {
    expect(refs("a.ts", `import x from "lodash/merge";`)[0]).toMatchObject({ pkg: "lodash" });
    expect(refs("a.ts", `import y from "@scope/pkg/deep/path";`)[0]).toMatchObject({ pkg: "@scope/pkg" });
  });

  it("ignores relative and absolute specifiers entirely", () => {
    expect(refs("a.ts", `import x from "./local";\nimport y from "../up";\nimport z from "/abs";`)).toEqual([]);
  });

  // Full-project dogfood 2026-07-10: standard modern Node imports were flagged
  // as non-existent npm packages — a false CRITICAL on virtually every real
  // codebase. Builtins are never registry-resolvable.
  it("ignores node: protocol imports and bare Node builtins", () => {
    expect(refs("a.ts", `import fs from "node:fs";`)).toEqual([]);
    expect(refs("a.mjs", `import { spawn } from "node:child_process";`)).toEqual([]);
    expect(refs("a.cjs", `const path = require("node:path");`)).toEqual([]);
    expect(refs("a.ts", `import fs from "fs";\nimport path from "path/posix";`)).toEqual([]);
  });

  // `@/x` (tsconfig alias shape) is not even a VALID npm name — the scope is
  // empty. It must never reach the registry, let alone produce a critical.
  it("ignores specifiers that cannot be valid npm names", () => {
    expect(refs("a.ts", `import { api } from "@/lib";`)).toEqual([]);
    expect(refs("a.tsx", `import { Shell } from "@/graneth/shell";`)).toEqual([]);
  });

  it("still extracts real scoped packages", () => {
    expect(refs("a.ts", `import { z } from "@scope/pkg";`)[0]).toMatchObject({ pkg: "@scope/pkg" });
  });
});

describe("python extraction forms", () => {
  it("import / from-import at line start, first segment only", () => {
    expect(refs("a.py", `import numpy`)[0]).toMatchObject({ pkg: "numpy", ecosystem: "pypi" });
    expect(refs("a.py", `from flask import request`)[0]).toMatchObject({ pkg: "flask" });
    expect(refs("a.py", `import numpy.linalg`)[0]).toMatchObject({ pkg: "numpy" });
  });

  it("normalizes underscores to dashes (registry naming)", () => {
    expect(refs("a.py", `import python_dateutil`)[0]).toMatchObject({ pkg: "python-dateutil" });
  });

  it("does not match indented (nested) imports or non-import lines", () => {
    expect(refs("a.py", `    import os_inside_function`)).toEqual([]);
    expect(refs("a.py", `x = "import fake"`)).toEqual([]);
  });

  it("tolerates multiple spaces after the import keyword (\\s+ semantics)", () => {
    expect(refs("a.py", `from   flask   import request`)[0]).toMatchObject({ pkg: "flask" });
    expect(refs("a.py", `import   numpy`)[0]).toMatchObject({ pkg: "numpy" });
  });
});

describe("non-ecosystem files", () => {
  it("files outside npm/pypi extensions yield no refs even with import-looking lines", () => {
    expect(refs("notes.txt", `import x from "some-lib";\nimport requests`)).toEqual([]);
  });
});

describe("dedup and location", () => {
  it("keeps the first-seen location per (pkg, ecosystem)", () => {
    const out = extractImportedPackages([
      { path: "a.ts", content: `import a from "dupe-lib";\nimport b from "dupe-lib";` },
      { path: "b.ts", content: `import c from "dupe-lib";` },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ filename: "a.ts", line: 1 });
  });

  it("the same name counts once per ecosystem", () => {
    const out = extractImportedPackages([
      { path: "a.ts", content: `import x from "requests";` },
      { path: "b.py", content: `import requests` },
    ]);
    expect(out).toHaveLength(2);
    expect(new Set(out.map((r) => r.ecosystem))).toEqual(new Set(["npm", "pypi"]));
  });
});
