/**
 * Manifest dependency extraction — package.json + requirements.txt.
 *
 * Closes the dogfood gap where dependencies declared straight in a manifest
 * (the most common way AI agents add packages) were never verified: only
 * import statements in source files were parsed. Parse failures are REPORTED
 * to the caller, never swallowed — a manifest we cannot read must not look
 * "clean" (same fail-safe contract as the server scanner).
 */

import type { FileInput, PackageRef } from "./imports.js";

export interface ManifestParseError {
  file: string;
  message: string;
}

export interface ManifestExtraction {
  refs: PackageRef[];
  errors: ManifestParseError[];
}

const NPM_DEP_SECTIONS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const;

/** Specifier protocols that do not resolve against the public npm registry. */
const NON_REGISTRY_SPEC = /^(?:workspace|file|link|portal|git\+[a-z]+|git|github|catalog|ssh|https?):/;

interface Accumulator extends ManifestExtraction {
  seen: Set<string>;
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1];
}

export type ManifestKind = "package.json" | "requirements" | "cargo" | "gomod" | "gemfile" | "composer";

/** Which manifest format a path is, by basename — or null for non-manifests. */
export function manifestKind(path: string): ManifestKind | null {
  const base = basename(path);
  if (base === "package.json") return "package.json";
  if (/requirements[^\\/]*\.txt$/i.test(base)) return "requirements";
  if (base === "Cargo.toml") return "cargo";
  if (base === "go.mod") return "gomod";
  if (base === "Gemfile") return "gemfile";
  if (base === "composer.json") return "composer";
  return null;
}

function pushRef(acc: Accumulator, ref: PackageRef): void {
  const key = `${ref.pkg}::${ref.ecosystem}`;
  if (!acc.seen.has(key)) {
    acc.seen.add(key);
    acc.refs.push(ref);
  }
}

/** `npm:pkg@range` / `npm:@scope/pkg@range` → the real registry target name. */
function npmAliasTarget(spec: string): string | null {
  const rest = spec.slice("npm:".length);
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  const name = at === -1 ? rest : rest.slice(0, at);
  return name || null;
}

/**
 * Resolve one package.json dependency entry to its registry target name, or
 * null when the specifier does not resolve against the public npm registry
 * (workspace/file/link/git/github-shorthand/URL/catalog). Shared with the
 * server's diff-level manifest scan so the two never drift.
 */
export function npmDependencyTarget(name: string, spec: string): string | null {
  if (spec.startsWith("npm:")) return npmAliasTarget(spec);
  // "user/repo" github shorthand is the only registry-invalid shape with a
  // slash that has no protocol prefix — version ranges never contain "/".
  if (NON_REGISTRY_SPEC.test(spec) || spec.includes("/")) return null;
  return name;
}

/** 1-indexed line where `"name"` is declared (1 if not found — still valid). */
function declarationLine(lines: string[], name: string): number {
  const needle = `"${name}"`;
  const idx = lines.findIndex((l) => l.includes(needle));
  return idx === -1 ? 1 : idx + 1;
}

function collectPackageJson(file: FileInput, acc: Accumulator): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(file.content);
  } catch (err) {
    acc.errors.push({ file: file.path, message: err instanceof Error ? err.message : String(err) });
    return;
  }
  if (typeof parsed !== "object" || parsed === null) return;
  const lines = file.content.split("\n");

  for (const section of NPM_DEP_SECTIONS) {
    const deps = (parsed as Record<string, unknown>)[section];
    if (typeof deps !== "object" || deps === null) continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof spec !== "string") continue;
      const target = npmDependencyTarget(name, spec);
      if (!target) continue;
      pushRef(acc, { pkg: target, filename: file.path, line: declarationLine(lines, name), ecosystem: "npm" });
    }
  }
}

/** pip option lines, local paths, URLs and direct references — no registry name to verify. */
function isNonRegistryRequirement(line: string): boolean {
  return (
    line.startsWith("-") ||
    line.startsWith(".") ||
    line.startsWith("/") ||
    line.includes("://") ||
    line.includes(" @ ")
  );
}

/**
 * Parse one requirements.txt line to a normalized PyPI name, or null for
 * comments, blanks, pip options, URLs, local paths and direct references.
 * Shared with the server's diff-level manifest scan so the two never drift.
 */
export function parseRequirementLine(raw: string): string | null {
  // pip comments start at `#` when at line start or preceded by whitespace
  const commentIdx = raw.search(/(?:^|\s)#/);
  const line = (commentIdx === -1 ? raw : raw.slice(0, commentIdx)).trim();
  if (!line || isNonRegistryRequirement(line)) return null;
  const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
  // PyPI treats `.`/`_`/`-` as equivalent; normalize like the import scanner does.
  return m ? m[1].replace(/[._]/g, "-") : null;
}

function collectRequirementsTxt(file: FileInput, acc: Accumulator): void {
  const lines = file.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const pkg = parseRequirementLine(lines[i]);
    if (pkg) pushRef(acc, { pkg, filename: file.path, line: i + 1, ecosystem: "pypi" });
  }
}

// ─── Cargo.toml (Rust) ────────────────────────────────────────────────────────

/** True for `[dependencies]`-family section headers (incl. target-specific). */
export function isCargoDepSection(header: string): boolean {
  return /^(?:workspace\.)?(?:dev-|build-)?dependencies$/.test(header)
    || /^target\.[^\]]+\.(?:dev-|build-)?dependencies$/.test(header);
}

/**
 * One `name = spec` line inside a Cargo dependencies section → the crates.io
 * name to verify, or null for path/git deps (never resolve on the registry).
 * A `package = "real"` rename inside an inline table wins over the alias key.
 */
export function cargoDependencyTarget(line: string): string | null {
  const m = line.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
  if (!m) return null;
  const [, key, rawSpec] = m;
  const spec = rawSpec.trim();
  if (spec.startsWith("{")) {
    if (/\b(?:path|git)\s*=/.test(spec)) return null; // local/git dep
    const rename = spec.match(/\bpackage\s*=\s*"([^"]+)"/);
    return rename ? rename[1] : key;
  }
  // plain `name = "1.0"` version-string form
  return /^"/.test(spec) ? key : null;
}

function collectCargoToml(file: FileInput, acc: Accumulator): void {
  const lines = file.content.split("\n");
  let inDepSection = false;
  let subtable: { name: string; line: number; renamed: string | null; local: boolean } | null = null;

  const flushSubtable = () => {
    if (subtable && !subtable.local) {
      pushRef(acc, { pkg: subtable.renamed ?? subtable.name, filename: file.path, line: subtable.line, ecosystem: "crates" });
    }
    subtable = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const header = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (header) {
      flushSubtable();
      const h = header[1].trim();
      // `[dependencies.NAME]` subtable form
      const sub = h.match(/^(?:workspace\.)?(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)$/);
      if (sub) { subtable = { name: sub[1], line: i + 1, renamed: null, local: false }; inDepSection = false; continue; }
      inDepSection = isCargoDepSection(h);
      continue;
    }
    if (subtable) {
      if (/^\s*(?:path|git)\s*=/.test(line)) subtable.local = true;
      const rename = line.match(/^\s*package\s*=\s*"([^"]+)"/);
      if (rename) subtable.renamed = rename[1];
      continue;
    }
    if (!inDepSection) continue;
    const pkg = cargoDependencyTarget(line);
    if (pkg) pushRef(acc, { pkg, filename: file.path, line: i + 1, ecosystem: "crates" });
  }
  flushSubtable();
}

// ─── go.mod ───────────────────────────────────────────────────────────────────

/**
 * One go.mod line → the module path required on that line, or null. Handles
 * both the single-line `require path vX` form and block-body `\tpath vX` lines.
 */
export function goModRequireTarget(line: string, inRequireBlock: boolean): string | null {
  const single = line.match(/^\s*require\s+([A-Za-z0-9][\w.~-]*\.[A-Za-z]{2,}(?:\/[\w.~-]+)+)\s+v\d/);
  if (single) return single[1];
  if (!inRequireBlock) return null;
  const block = line.match(/^\s*([A-Za-z0-9][\w.~-]*\.[A-Za-z]{2,}(?:\/[\w.~-]+)+)\s+v\d/);
  return block ? block[1] : null;
}

/** Module paths replaced by a LOCAL filesystem path — they never hit the proxy. */
function goModLocalReplacements(lines: string[]): Set<string> {
  const replaced = new Set<string>();
  let inBlock = false;
  for (const line of lines) {
    if (/^\s*replace\s*\(/.test(line)) { inBlock = true; continue; }
    if (inBlock && /^\s*\)/.test(line)) { inBlock = false; continue; }
    const m = line.match(/^\s*(?:replace\s+)?(\S+)(?:\s+\S+)?\s+=>\s+(\S+)/);
    if (!m) continue;
    if (!inBlock && !/^\s*replace\s/.test(line)) continue;
    const target = m[2];
    if (target.startsWith("./") || target.startsWith("../") || target.startsWith("/")) replaced.add(m[1]);
  }
  return replaced;
}

function collectGoMod(file: FileInput, acc: Accumulator): void {
  const lines = file.content.split("\n");
  const localReplaced = goModLocalReplacements(lines);
  let inRequire = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*require\s*\(/.test(line)) { inRequire = true; continue; }
    if (inRequire && /^\s*\)/.test(line)) { inRequire = false; continue; }
    const pkg = goModRequireTarget(line, inRequire);
    if (pkg && !localReplaced.has(pkg)) {
      pushRef(acc, { pkg, filename: file.path, line: i + 1, ecosystem: "go" });
    }
  }
}

// ─── Gemfile (Ruby) ───────────────────────────────────────────────────────────

/**
 * One Gemfile line → the gem name to verify against rubygems.org, or null.
 * Gems sourced from path:/git:/github:/gist: never resolve on the registry.
 */
export function gemfileTarget(line: string): string | null {
  const trimmed = line.trim();
  if (trimmed.startsWith("#")) return null;
  const m = trimmed.match(/^gem\s+["']([A-Za-z0-9._-]+)["'](.*)$/);
  if (!m) return null;
  // `path:`/`git:`… (modern) and `:path =>`… (hashrocket) option syntaxes both
  // mean the gem is not registry-sourced.
  if (/(?:^|[\s,:])(?:path|git|github|gist|branch)\s*(?::|=>)/.test(m[2])) return null;
  return m[1];
}

function collectGemfile(file: FileInput, acc: Accumulator): void {
  const lines = file.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const pkg = gemfileTarget(lines[i]);
    if (pkg) pushRef(acc, { pkg, filename: file.path, line: i + 1, ecosystem: "gems" });
  }
}

// ─── composer.json (PHP) ──────────────────────────────────────────────────────

/** Platform requirements (php runtime, extensions, system libs) — not Packagist names. */
export function isComposerPlatformPackage(name: string): boolean {
  return name === "php" || /^php-/.test(name) || name === "hhvm" || /^ext-/.test(name) || /^lib-/.test(name);
}

/** True when a composer dependency name is a verifiable vendor/package pair. */
export function isComposerPackageName(name: string): boolean {
  return /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9]([_.-]?[a-z0-9]+)*$/.test(name);
}

function collectComposerJson(file: FileInput, acc: Accumulator): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(file.content);
  } catch (err) {
    acc.errors.push({ file: file.path, message: err instanceof Error ? err.message : String(err) });
    return;
  }
  if (typeof parsed !== "object" || parsed === null) return;
  const lines = file.content.split("\n");

  for (const section of ["require", "require-dev"] as const) {
    const deps = (parsed as Record<string, unknown>)[section];
    if (typeof deps !== "object" || deps === null) continue;
    for (const name of Object.keys(deps as Record<string, unknown>)) {
      if (isComposerPlatformPackage(name) || !isComposerPackageName(name)) continue;
      pushRef(acc, { pkg: name, filename: file.path, line: declarationLine(lines, name), ecosystem: "composer" });
    }
  }
}

/** Extract registry-resolvable dependency declarations from manifest files. */
export function extractManifestPackages(files: FileInput[]): ManifestExtraction {
  const acc: Accumulator = { refs: [], errors: [], seen: new Set() };
  for (const file of files) {
    const kind = manifestKind(file.path);
    if (kind === "package.json") collectPackageJson(file, acc);
    else if (kind === "requirements") collectRequirementsTxt(file, acc);
    else if (kind === "cargo") collectCargoToml(file, acc);
    else if (kind === "gomod") collectGoMod(file, acc);
    else if (kind === "gemfile") collectGemfile(file, acc);
    else if (kind === "composer") collectComposerJson(file, acc);
  }
  return { refs: acc.refs, errors: acc.errors };
}
