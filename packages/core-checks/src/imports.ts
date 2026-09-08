/**
 * Import extraction — find package references in raw file content.
 *
 * Same import regexes as server/governance/supply-chain/packageVerifier.ts (extractPackageRefs)
 * but operating on full file content (the MCP server receives whole files, not
 * diffs).
 */

import type { Ecosystem } from "./types.js";

const PY_EXT = /\.(py|pyw|pyi)$/i;
// `.mts`/`.cts` are the TypeScript halves of the `.mjs`/`.cjs` pair that was
// already here, standard since TS 4.7. Without them `primaryEcosystem` returns
// null and the file is skipped whole — not one import form missed, every line
// unread. This repository ships two of them.
const JS_EXT = /\.(js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i;
const RUST_EXT = /\.rs$/i;
const GO_EXT = /\.go$/i;
// NOTE: .rb and .php get NO import-based extraction on purpose. Ruby `require`
// takes file paths that don't map to gem names (and overlaps stdlib), PHP `use`
// takes namespaces, not package names — both would produce false ghost
// criticals. Their manifests (Gemfile / composer.json) are the reliable source.

// Node builtins are never registry names — `node:fs` / `fs` / `fs/promises`
// flagged as "does not exist in npm" was a false CRITICAL on virtually every
// real codebase (found by the 2026-07-10 full-project dogfood).
//
// The list is inlined instead of read from `node:module`.builtinModules: this
// module is part of the shared core, and the browser bundle imports the same
// barrel (the landing's package check). A static `import … from "node:module"`
// resolves to Vite's browser stub, and touching `builtinModules` on it THROWS
// at module init — which blanked the entire landing. A pinned list works in
// every runtime; `isNodeBuiltin` is unit-tested against Node's own list, so
// drift fails CI rather than silently shipping a false CRITICAL.
const NODE_BUILTINS = new Set([
  "assert",
  "assert/strict",
  "async_hooks",
  "buffer",
  "child_process",
  "cluster",
  "console",
  "constants",
  "crypto",
  "dgram",
  "diagnostics_channel",
  "dns",
  "dns/promises",
  "domain",
  "events",
  "fs",
  "fs/promises",
  "http",
  "http2",
  "https",
  "inspector",
  "inspector/promises",
  "module",
  "net",
  "os",
  "path",
  "path/posix",
  "path/win32",
  "perf_hooks",
  "process",
  "punycode",
  "querystring",
  "readline",
  "readline/promises",
  "repl",
  "sea",
  "sqlite",
  "stream",
  "stream/consumers",
  "stream/promises",
  "stream/web",
  "string_decoder",
  "sys",
  "test",
  "test/reporters",
  "timers",
  "timers/promises",
  "tls",
  "trace_events",
  "tty",
  "url",
  "util",
  "util/types",
  "v8",
  "vm",
  "wasi",
  "worker_threads",
  "zlib",
]);

/**
 * Specifier roots that are a PATH, not a package. `node_modules/x` is where
 * packages live, never a name on the registry.
 */
const NOT_A_PACKAGE_ROOT = new Set(["node_modules"]);

/** A bare specifier that Node resolves to a builtin (with or without `node:`). */
export function isNodeBuiltin(name: string): boolean {
  return (
    name.startsWith("node:") ||
    NODE_BUILTINS.has(name) ||
    NOT_A_PACKAGE_ROOT.has(name)
  );
}

/**
 * True when an extracted package root could actually resolve on the npm
 * registry: not a node: builtin, and a syntactically valid npm name (a scope,
 * when present, must be non-empty — `@/lib`-style tsconfig aliases are not
 * npm names and must never reach the registry).
 */
export function isResolvableNpmName(name: string): boolean {
  if (isNodeBuiltin(name)) return false;
  return /^(?:@[a-z0-9~][\w.~-]*\/)?[a-z0-9~][\w.~-]*$/i.test(name);
}

export function primaryEcosystem(filename: string): Ecosystem | null {
  if (PY_EXT.test(filename)) return "pypi";
  if (JS_EXT.test(filename)) return "npm";
  if (RUST_EXT.test(filename)) return "crates";
  if (GO_EXT.test(filename)) return "go";
  return null;
}

// ─── Rust ─────────────────────────────────────────────────────────────────────

// Rust path roots that are never crates.io names: the std library facade,
// local-module keywords, and compiler-shipped crates.
const RUST_BUILTIN_ROOTS = new Set([
  "std",
  "core",
  "alloc",
  "crate",
  "self",
  "super",
  "proc_macro",
  "test",
]);

/** `use serde_json::Value;` / `extern crate rand;` → crate root, or null. */
export function rustCrateFromLine(content: string): string | null {
  const m = content.match(
    /^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([A-Za-z_][A-Za-z0-9_-]*)/
  );
  if (!m) return null;
  const root = m[1];
  return RUST_BUILTIN_ROOTS.has(root) ? null : root;
}

// ─── Go ───────────────────────────────────────────────────────────────────────

/**
 * Collapse a Go import path to its module root for hosts whose layout is
 * known. Returns null for stdlib (no dot in the first segment) and for unknown
 * vanity hosts — guessing a wrong module root would 404 on the proxy and
 * produce a false ghost critical, so unknown hosts are conservatively skipped
 * (go.mod, which lists EXACT module paths, covers them).
 */
export function goModuleRoot(importPath: string): string | null {
  const segs = importPath.split("/");
  if (!segs[0].includes(".")) return null; // stdlib: fmt, net/http, …
  const host = segs[0].toLowerCase();
  if (
    host === "github.com" ||
    host === "gitlab.com" ||
    host === "bitbucket.org"
  ) {
    return segs.length >= 3 ? segs.slice(0, 3).join("/") : null;
  }
  if (host === "golang.org" && segs[1] === "x") {
    return segs.length >= 3 ? segs.slice(0, 3).join("/") : null;
  }
  if (host === "gopkg.in") {
    // gopkg.in/yaml.v3 (2 segments) vs gopkg.in/user/pkg.v1 (3 segments)
    if (segs.length >= 2 && segs[1].includes(".v"))
      return segs.slice(0, 2).join("/");
    return segs.length >= 3 ? segs.slice(0, 3).join("/") : null;
  }
  return null;
}

/** One line inside/outside an import block → module root, or null. */
export function goModuleFromLine(
  content: string,
  inImportBlock: boolean
): string | null {
  // single-line form: import "path"  |  import alias "path"
  const single = content.match(
    /^\s*import\s+(?:[A-Za-z_.][\w.]*\s+)?"([^"]+)"/
  );
  if (single) return goModuleRoot(single[1]);
  if (!inImportBlock) return null;
  // block body: \t"path"  |  \talias "path"
  const block = content.match(/^\s*(?:[A-Za-z_.][\w.]*\s+)?"([^"]+)"\s*$/);
  return block ? goModuleRoot(block[1]) : null;
}

export interface PackageRef {
  pkg: string;
  filename: string;
  line: number;
  ecosystem: Ecosystem;
  /**
   * Where the reference came from, because it decides whether a miss can block.
   *
   * A name written into a MANIFEST is a declared dependency: if the registry
   * does not have it, that is demonstrable and somebody has to act. A bare
   * IMPORT specifier is not — it may be a path alias, a workspace package or a
   * typo, and a diff-scoped check usually lacks the `tsconfig.json` that would
   * say which. Measured over this repository's own history: every one of 76
   * production-path criticals was an internal name reached through an import.
   */
  source?: "manifest" | "import";
}

/** Parse a single source line into a package name (or null). */
const packageRoot = (spec: string): string =>
  spec.startsWith("@")
    ? spec.split("/").slice(0, 2).join("/")
    : spec.split("/")[0];

function packageFromLine(content: string, eco: Ecosystem): string | null {
  // Ecosystem-routed on purpose: the python fallback used to run on JS/TS
  // lines too, so a RELATIVE import (`import Config from "./config"`) — which
  // no JS regex matches — fell through and returned the BINDING name as a
  // "package", producing false ghost-package criticals on real code.
  // The excluded first characters are `.` and `/` (relative and absolute) plus
  // `~` and `#`: the first is a bundler path alias, the second is Node's own
  // subpath-imports prefix. Neither is ever a name on a registry.
  if (eco === "npm") {
    // Quotes must MATCH (backreference): a fragment like `"flask-' + '…` in a
    // string-literal code sample used to satisfy [open "][^'"]*[close '] and
    // produce a ghost ref for a name that appears in no real import.
    // Static ESM: `import x from 'pkg'`, `import 'pkg'`
    const esm = content.match(
      /import\s+(?:[^'"]*\s+from\s+)?(['"])([^'"./~#][^'"]*)\1/
    );
    if (esm) return packageRoot(esm[2]);
    // Dynamic import: `import('pkg')`, `await import('pkg')` — common in AI-generated
    // code (lazy/conditional loading); a blind spot if only static imports are scanned.
    const dyn = content.match(/import\s*\(\s*(['"])([^'"./~#][^'"]*)\1\s*\)/);
    if (dyn) return packageRoot(dyn[2]);
    // Re-export: `export { a } from 'pkg'`, `export * from 'pkg'` (barrel files).
    const reexport = content.match(
      /export\s+[^'"]*\bfrom\s+(['"])([^'"./~#][^'"]*)\1/
    );
    if (reexport) return packageRoot(reexport[2]);
    // CommonJS: `require('pkg')`
    const cjs = content.match(/require\s*\(\s*(['"])([^'"./~#][^'"]*)\1\s*\)/);
    if (cjs) return cjs[2].split("/")[0];
    // ── THE CLOSING LINE OF A WRAPPED IMPORT ────────────────────────────────
    //
    // Every clause above needs the keyword and the specifier on ONE line, and
    // this walker is applied line by line. Prettier's default printWidth wraps
    // any import with more than a couple of named bindings, leaving
    // `} from "pkg";` alone on the closing line with no `import` on it — so the
    // single most common formatting of a long import in a real repository
    // produced NO package reference at all, and a hallucinated name imported
    // that way came back CLEAR. Measured in this tree: 23 such specifiers
    // across 883 TS/JS files, invisible.
    //
    // Anchored to the start of the line so it cannot match `from` inside prose
    // or a string; relative and absolute specifiers excluded as everywhere
    // else. Covers the wrapped `export { … } from "pkg"` form too.
    const wrapped = content.match(/^\s*\}?\s*from\s+(['"])([^'"./~#][^'"]*)\1/);
    if (wrapped) return packageRoot(wrapped[2]);
    return null;
  }
  if (eco === "crates") return rustCrateFromLine(content);
  // Python: `import pkg`, `from pkg import ...`
  //
  // `^\s*`, not `^`. Rust (`rustCrateFromLine`) and Go (`goModuleFromLine`)
  // both allow leading whitespace and the npm clauses are unanchored — Python
  // alone demanded column zero, so a lazy import inside a function, a
  // `try: import x / except ImportError`, and an `if TYPE_CHECKING:` block all
  // extracted nothing. Those are exactly the forms a model emits for an
  // optional dependency, and `pyproject.toml` is deliberately not a manifest
  // here, so for many Python repositories the import scan is the only place a
  // PyPI name could have been seen at all.
  const py = content.match(
    /^\s*(?:import|from)\s+([A-Za-z][A-Za-z0-9_-]*)(?:\s|$|\.)/
  );
  if (py) return py[1].replace(/_/g, "-");
  return null;
}

/** Go files need per-file import-block state, so they get their own walker. */
function extractGoRefs(file: FileInput, seen: Map<string, PackageRef>): void {
  const lines = file.content.split("\n");
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*import\s*\(/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && /^\s*\)/.test(line)) {
      inBlock = false;
      continue;
    }
    const pkg = goModuleFromLine(line, inBlock);
    if (!pkg) continue;
    const key = `${pkg}::go`;
    if (!seen.has(key))
      seen.set(key, { pkg, filename: file.path, line: i + 1, ecosystem: "go" });
  }
}

export interface FileInput {
  path: string;
  content: string;
}

/**
 * One line, split into the import statements it actually contains.
 *
 * Only Python needs this, and only for the `import a, b` form: `packageFromLine`
 * matches once per string, so `import os, huggingface_cli` yielded `os` and
 * stopped — a hallucinated package sharing a line with a stdlib module was
 * invisible, which is exactly how a model writes it. `from x import a, b` is
 * untouched: everything after `import` there is a symbol, not a package.
 */
function importSegments(line: string, eco: Ecosystem): string[] {
  if (eco !== "pypi") return [line];
  const m = line.match(/^(\s*)import\s+(.+)$/);
  if (!m || !m[2].includes(",")) return [line];
  return m[2].split(",").map(part => `${m[1]}import ${part.trim()}`);
}

/**
 * PYTHON STANDARD-LIBRARY MODULES — the filter every other ecosystem had.
 *
 * npm has `NODE_BUILTINS`, Rust has `RUST_BUILTIN_ROOTS`, Go treats a first
 * segment with no dot as stdlib. Python had nothing, so `import os` produced a
 * package reference, PyPI answered 404 — verified live: os, sys, json and re
 * all 404 — and the tool reported a CRITICAL saying the package "does not
 * exist". A critical forces BLOCKED, so the most common import in the language
 * blocked every commit touching a Python file.
 *
 * Generated from `sys.stdlib_module_names` on CPython 3.12, plus modules
 * removed in recent versions that real code still imports (`distutils`, `imp`,
 * the PEP 594 removals). Private `_`-prefixed names are excluded: nobody
 * imports them. Stored with `_` folded to `-`, which is the normalisation
 * `packageFromLine` applies before this is consulted.
 *
 * A name here is never looked up and never reported. The cost of the list
 * going slightly stale is one stdlib module checked against PyPI; the cost of
 * not having it was a false CRITICAL on every Python file.
 */
const PY_STDLIB = new Set([
  "abc",
  "aifc",
  "antigravity",
  "argparse",
  "array",
  "ast",
  "asynchat",
  "asyncio",
  "asyncore",
  "atexit",
  "audioop",
  "base64",
  "bdb",
  "binascii",
  "bisect",
  "builtins",
  "bz2",
  "cProfile",
  "calendar",
  "cgi",
  "cgitb",
  "chunk",
  "cmath",
  "cmd",
  "code",
  "codecs",
  "codeop",
  "collections",
  "colorsys",
  "compileall",
  "concurrent",
  "configparser",
  "contextlib",
  "contextvars",
  "copy",
  "copyreg",
  "crypt",
  "csv",
  "ctypes",
  "curses",
  "dataclasses",
  "datetime",
  "dbm",
  "decimal",
  "difflib",
  "dis",
  "distutils",
  "doctest",
  "email",
  "encodings",
  "ensurepip",
  "enum",
  "errno",
  "faulthandler",
  "fcntl",
  "filecmp",
  "fileinput",
  "fnmatch",
  "fractions",
  "ftplib",
  "functools",
  "gc",
  "genericpath",
  "getopt",
  "getpass",
  "gettext",
  "glob",
  "graphlib",
  "grp",
  "gzip",
  "hashlib",
  "heapq",
  "hmac",
  "html",
  "http",
  "idlelib",
  "imaplib",
  "imghdr",
  "imp",
  "importlib",
  "inspect",
  "io",
  "ipaddress",
  "itertools",
  "json",
  "keyword",
  "lib2to3",
  "linecache",
  "locale",
  "logging",
  "lzma",
  "mailbox",
  "mailcap",
  "marshal",
  "math",
  "mimetypes",
  "mmap",
  "modulefinder",
  "msilib",
  "msvcrt",
  "multiprocessing",
  "netrc",
  "nis",
  "nntplib",
  "nt",
  "ntpath",
  "nturl2path",
  "numbers",
  "opcode",
  "operator",
  "optparse",
  "os",
  "ossaudiodev",
  "pathlib",
  "pdb",
  "pickle",
  "pickletools",
  "pipes",
  "pkgutil",
  "platform",
  "plistlib",
  "poplib",
  "posix",
  "posixpath",
  "pprint",
  "profile",
  "pstats",
  "pty",
  "pwd",
  "py-compile",
  "pyclbr",
  "pydoc",
  "pydoc-data",
  "pyexpat",
  "queue",
  "quopri",
  "random",
  "re",
  "readline",
  "reprlib",
  "resource",
  "rlcompleter",
  "runpy",
  "sched",
  "secrets",
  "select",
  "selectors",
  "shelve",
  "shlex",
  "shutil",
  "signal",
  "site",
  "smtpd",
  "smtplib",
  "sndhdr",
  "socket",
  "socketserver",
  "spwd",
  "sqlite3",
  "sre-compile",
  "sre-constants",
  "sre-parse",
  "ssl",
  "stat",
  "statistics",
  "string",
  "stringprep",
  "struct",
  "subprocess",
  "sunau",
  "symtable",
  "sys",
  "sysconfig",
  "syslog",
  "tabnanny",
  "tarfile",
  "telnetlib",
  "tempfile",
  "termios",
  "textwrap",
  "this",
  "threading",
  "time",
  "timeit",
  "tkinter",
  "token",
  "tokenize",
  "tomllib",
  "trace",
  "traceback",
  "tracemalloc",
  "tty",
  "turtle",
  "turtledemo",
  "types",
  "typing",
  "unicodedata",
  "unittest",
  "urllib",
  "uu",
  "uuid",
  "venv",
  "warnings",
  "wave",
  "weakref",
  "webbrowser",
  "winreg",
  "winsound",
  "wsgiref",
  "xdrlib",
  "xml",
  "xmlrpc",
  "zipapp",
  "zipfile",
  "zipimport",
  "zlib",
  "zoneinfo",
]);

/** True for a module the interpreter ships — never a PyPI package. */
export function isPythonStdlib(name: string): boolean {
  return PY_STDLIB.has(name);
}

/** Extract unique (pkg, ecosystem) references with first-seen location. */
export function extractImportedPackages(files: FileInput[]): PackageRef[] {
  const seen = new Map<string, PackageRef>();

  for (const file of files) {
    const eco = primaryEcosystem(file.path);
    if (!eco) continue;
    if (eco === "go") {
      extractGoRefs(file, seen);
      continue;
    }

    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const segment of importSegments(lines[i], eco)) {
        const pkg = packageFromLine(segment, eco);
        if (!pkg) continue;
        if (eco === "npm" && !isResolvableNpmName(pkg)) continue;
        if (eco === "pypi" && isPythonStdlib(pkg)) continue;
        const key = `${pkg}::${eco}`;
        if (!seen.has(key)) {
          seen.set(key, {
            pkg,
            filename: file.path,
            line: i + 1,
            ecosystem: eco,
          });
        }
      }
    }
  }
  return Array.from(seen.values());
}
