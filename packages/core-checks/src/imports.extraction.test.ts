import { describe, it, expect } from "vitest";
import { extractImportedPackages } from "@graneth/core-checks";

const pkgs = (content: string, path = "a.ts") =>
  extractImportedPackages([{ path, content }]).map(r => r.pkg);

/**
 * Regression guard: dynamic import() and re-exports were previously NOT extracted,
 * so a hallucinated / typosquatted package loaded those ways slipped past the
 * ghost-package and typosquat checks entirely. These forms are common in
 * AI-generated code (lazy/conditional imports) and barrel files.
 */
describe("import extraction — package-check evasion forms", () => {
  it("baseline forms still work", () => {
    expect(pkgs("import x from 'lodash'")).toEqual(["lodash"]);
    expect(pkgs("import 'malware-pkg'")).toEqual(["malware-pkg"]);
    expect(pkgs("const y = require('reqeusts')")).toEqual(["reqeusts"]);
    expect(pkgs("import { z } from '@scope/pkg'")).toEqual(["@scope/pkg"]);
  });

  it("catches dynamic import() — previously a blind spot", () => {
    expect(pkgs("const m = await import('evil-hallucinated-pkg')")).toEqual([
      "evil-hallucinated-pkg",
    ]);
    expect(pkgs("import('lazy-pkg').then(m => m.run())")).toEqual(["lazy-pkg"]);
  });

  it("catches re-exports — previously a blind spot", () => {
    expect(pkgs("export { a } from 'sketchy-pkg'")).toEqual(["sketchy-pkg"]);
    expect(pkgs("export * from 'barrel-pkg'")).toEqual(["barrel-pkg"]);
    expect(pkgs("export type { T } from '@scope/types-pkg'")).toEqual([
      "@scope/types-pkg",
    ]);
  });

  it("python forms (.py)", () => {
    expect(pkgs("from evil_pkg import x", "a.py")).toEqual(["evil-pkg"]);
    expect(pkgs("import flask_gpt_helper", "a.py")).toEqual([
      "flask-gpt-helper",
    ]);
  });

  it("does NOT misfire on a plain string export with no 'from' clause", () => {
    expect(pkgs('export const API = "https://example.com"')).toEqual([]);
    expect(pkgs("export const NAME = 'not-a-package'")).toEqual([]);
  });
});

/**
 * THE FORMS A REAL REPOSITORY ACTUALLY CONTAINS.
 *
 * Every clause of the npm matcher needed the keyword and the specifier on ONE
 * line, and the walker runs line by line — so prettier's default wrapping, the
 * single most common formatting of a long import in any TS/JS project, produced
 * no package reference at all. A hallucinated name imported that way came back
 * CLEAR, which is the one outcome this product exists to prevent. Measured in
 * this tree before the fix: 23 invisible specifiers across 883 files.
 *
 * Python had the mirror-image gap: its regex demanded column zero, while Rust
 * and Go had always allowed indentation. A lazy import inside a function, or an
 * `except ImportError` fallback — exactly what a model writes for an optional
 * dependency — extracted nothing.
 */
describe("imports a formatter wrapped are still imports", () => {
  const wrapped = (spec: string) =>
    `import {\n  aLongBindingName,\n  anotherLongBindingName,\n} from "${spec}";\n`;

  it("sees the specifier on the closing line of a wrapped import", () => {
    expect(
      extractImportedPackages([
        { path: "src/a.ts", content: wrapped("express-gpt") },
      ])
    ).toEqual([
      expect.objectContaining({ pkg: "express-gpt", ecosystem: "npm" }),
    ]);
  });

  it("sees it on a wrapped re-export too", () => {
    expect(
      extractImportedPackages([
        {
          path: "src/a.ts",
          content: `export {\n  a,\n  b,\n} from "express-gpt";\n`,
        },
      ])
    ).toEqual([expect.objectContaining({ pkg: "express-gpt" })]);
  });

  it("takes the package root from a wrapped deep import", () => {
    expect(
      extractImportedPackages([
        { path: "src/a.ts", content: wrapped("@scope/pkg/sub/path") },
      ])
    ).toEqual([expect.objectContaining({ pkg: "@scope/pkg" })]);
  });

  it("still ignores a wrapped RELATIVE import, which is not a package", () => {
    expect(
      extractImportedPackages([
        { path: "src/a.ts", content: wrapped("./config") },
      ])
    ).toEqual([]);
    expect(
      extractImportedPackages([
        { path: "src/a.ts", content: wrapped("../lib/x") },
      ])
    ).toEqual([]);
  });

  it("does not invent a package from the word `from` in prose or a string", () => {
    // The clause is line-anchored precisely so a comment or a message cannot
    // reach it. A false CRITICAL on a code comment would be its own defect.
    const content = [
      '// copied from "some-blog-post"',
      'const msg = `imported from "not-a-package"`;',
      'log("data from \\"nowhere\\"");',
    ].join("\n");

    expect(extractImportedPackages([{ path: "src/a.ts", content }])).toEqual(
      []
    );
  });

  it("counts a package once when it appears wrapped and inline", () => {
    const content = `import x from "express-gpt";\n` + wrapped("express-gpt");

    expect(
      extractImportedPackages([{ path: "src/a.ts", content }])
    ).toHaveLength(1);
  });
});

describe("Python imports that are not at column zero", () => {
  it("sees a lazy import inside a function", () => {
    expect(
      extractImportedPackages([
        {
          path: "app.py",
          content: "def load():\n    import huggingface_cli\n    return 1\n",
        },
      ])
    ).toEqual([
      expect.objectContaining({ pkg: "huggingface-cli", ecosystem: "pypi" }),
    ]);
  });

  it("sees the optional-dependency shape a model writes", () => {
    expect(
      extractImportedPackages([
        {
          path: "app.py",
          content:
            "try:\n    from fastapi_utilities import x\nexcept ImportError:\n    x = None\n",
        },
      ])
    ).toEqual([
      expect.objectContaining({ pkg: "fastapi-utilities", ecosystem: "pypi" }),
    ]);
  });

  it("sees a TYPE_CHECKING import", () => {
    expect(
      extractImportedPackages([
        {
          path: "app.py",
          content: "if TYPE_CHECKING:\n    from pandas_helper import Frame\n",
        },
      ])
    ).toEqual([
      expect.objectContaining({ pkg: "pandas-helper", ecosystem: "pypi" }),
    ]);
  });

  it("still refuses a quoted `import` inside a string", () => {
    // The reason the anchor existed. Loosening it to `^\s*` must not loosen
    // that: a name mentioned in a string is not a dependency.
    expect(
      extractImportedPackages([
        { path: "app.py", content: 'x = "import fake_package"\n' },
      ])
    ).toEqual([]);
  });
});

describe("the TypeScript module extensions", () => {
  it("reads .mts and .cts, which are the halves of the pair already covered", () => {
    for (const ext of ["mts", "cts"]) {
      expect(
        extractImportedPackages([
          {
            path: `scripts/tool.${ext}`,
            content: 'import x from "express-gpt";\n',
          },
        ]),
        `.${ext} files are skipped whole`
      ).toEqual([expect.objectContaining({ pkg: "express-gpt" })]);
    }
  });
});

describe("a hallucinated package sharing a line with a real one", () => {
  it("is extracted from a comma-joined Python import", () => {
    // `packageFromLine` matches once per string, so `import os, x` yielded `os`
    // and stopped. A model writes exactly this when it adds one dependency
    // beside a stdlib module.
    const out = extractImportedPackages([
      { path: "app.py", content: "import os, huggingface_cli\n" },
    ]);

    // `os` is stdlib and is filtered — the point of the split is that the
    // name BESIDE it is no longer invisible.
    expect(out.map(r => r.pkg)).toEqual(["huggingface-cli"]);
  });

  it("handles an alias in the same list", () => {
    const out = extractImportedPackages([
      { path: "app.py", content: "import numpy as np, huggingface_cli\n" },
    ]);

    expect(out.map(r => r.pkg)).toContain("huggingface-cli");
  });

  it("keeps the indented form working when it is also comma-joined", () => {
    const out = extractImportedPackages([
      { path: "app.py", content: "def f():\n    import os, huggingface_cli\n" },
    ]);

    expect(out.map(r => r.pkg)).toContain("huggingface-cli");
  });

  it("does NOT split `from x import a, b`, where the commas are symbols", () => {
    // Everything after `import` there is a name inside the module, not a
    // package. Splitting would invent `Dict` as a dependency.
    const out = extractImportedPackages([
      { path: "app.py", content: "from typing import List, Dict\n" },
    ]);

    // `typing` is stdlib, so nothing is extracted at all — and that is the
    // assertion: neither `List` nor `Dict` was invented as a dependency.
    expect(out.map(r => r.pkg)).toEqual([]);
  });

  it("reports them all at the line they share", () => {
    const out = extractImportedPackages([
      { path: "app.py", content: "x = 1\nimport os, huggingface_cli\n" },
    ]);

    for (const ref of out) expect(ref.line).toBe(2);
  });
});
