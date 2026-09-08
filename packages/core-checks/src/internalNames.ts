/**
 * Evidence-based internal-name resolution (issue #152).
 *
 * A valid-looking scoped import that 404s on npm is either a hallucination
 * (a real attack shape the benchmark covers) or a workspace/tsconfig-alias
 * name. We only treat it as internal when the scanned payload itself carries
 * the evidence — a tsconfig path mapping or a workspace manifest. No
 * evidence → the detector keeps failing toward detection.
 */

import type { FileInput } from "./imports.js";

export interface InternalNameEvidence {
  exact: Set<string>;
  /** Path-alias prefixes derived from `paths` keys ending in `/*`, kept with the trailing slash. */
  prefixes: string[];
}

const TSCONFIG_RE = /^tsconfig[^\\/]*\.json$/i;
const WORKSPACE_SPEC_RE = /^(?:workspace|file|link|portal):/;
const DEP_SECTIONS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
] as const;

/**
 * tsconfig is JSONC — strip line/block comments before parsing. String-aware:
 * `paths` values like "./src/*" contain `/*`, so a regex strip corrupts
 * exactly the config this module exists to read.
 */
/** Index just past the closing quote of the JSON string opening at `start`. */
function endOfJsonString(s: string, start: number): number {
  let i = start + 1;
  while (i < s.length) {
    if (s[i] === "\\") i += 2;
    else if (s[i] === '"') return i + 1;
    else i++;
  }
  return i;
}

function stripJsonComments(s: string): string {
  let out = "";
  let i = 0;
  while (i < s.length) {
    if (s[i] === '"') {
      const end = endOfJsonString(s, i);
      out += s.slice(i, end);
      i = end;
    } else if (s[i] === "/" && s[i + 1] === "/") {
      const eol = s.indexOf("\n", i);
      i = eol === -1 ? s.length : eol; // keep the newline itself
    } else if (s[i] === "/" && s[i + 1] === "*") {
      const close = s.indexOf("*/", i + 2);
      i = close === -1 ? s.length : close + 2;
    } else {
      out += s[i];
      i++;
    }
  }
  return out;
}

function collectTsconfigPaths(content: string, ev: InternalNameEvidence): void {
  try {
    const cfg = JSON.parse(stripJsonComments(content));
    const paths = cfg?.compilerOptions?.paths;
    if (!paths || typeof paths !== "object") return;
    for (const key of Object.keys(paths)) {
      if (key.endsWith("/*")) ev.prefixes.push(key.slice(0, -1));
      else ev.exact.add(key);
    }
  } catch {
    /* unparsable tsconfig = no evidence — detection stays on */
  }
}

function collectManifestNames(content: string, ev: InternalNameEvidence): void {
  try {
    const pkg = JSON.parse(content);
    if (typeof pkg?.name === "string" && pkg.name) ev.exact.add(pkg.name);
    for (const section of DEP_SECTIONS) {
      const deps = pkg?.[section];
      if (!deps || typeof deps !== "object") continue;
      for (const [name, spec] of Object.entries(deps)) {
        if (typeof spec === "string" && WORKSPACE_SPEC_RE.test(spec))
          ev.exact.add(name);
      }
    }
  } catch {
    /* manifests.ts already surfaces unparsable dependency manifests */
  }
}

/** Gather internal-name evidence from tsconfig + package.json files in the payload. */
export function extractInternalNameEvidence(
  files: FileInput[]
): InternalNameEvidence {
  const ev: InternalNameEvidence = { exact: new Set(), prefixes: [] };
  for (const file of files) {
    const base = file.path.split(/[\\/]/).pop() ?? "";
    if (TSCONFIG_RE.test(base)) collectTsconfigPaths(file.content, ev);
    else if (base === "package.json") collectManifestNames(file.content, ev);
  }
  return ev;
}

/** True when the payload proves this import specifier is workspace-internal. */
export function isInternalName(
  name: string,
  ev: InternalNameEvidence
): boolean {
  if (ev.exact.has(name)) return true;
  return ev.prefixes.some(p => name.startsWith(p) || `${name}/` === p);
}
