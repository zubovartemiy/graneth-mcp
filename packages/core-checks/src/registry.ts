/**
 * Live package-registry existence check — npm + PyPI, no DB, no cache.
 *
 * Answers the single juridically-unambiguous question that powers the
 * slopsquatting / AI-hallucination check: "does this package actually exist?"
 *
 * This mirrors the existence/age logic in
 * server/governance/supply-chain/packageVerifier.ts (fetchNpm / fetchPypi) but without the
 * Postgres cache layer, so it can run account-free inside the standalone MCP
 * server. The server keeps its richer DB-cached signal; this is the portable core.
 */

import type { Ecosystem } from "./types.js";

const NEW_PACKAGE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export interface RegistryResult {
  exists: boolean;
  isNewPackage: boolean;
  publishedAt: Date | null;
  /** Set when the registry was unreachable — caller should fail open. */
  unreachable?: boolean;
  // ── npm-only trust signals, extracted from the SAME packument (no extra
  //    fetch) so the account-free MCP can risk-score at generation time. ──
  /** Latest version declares a preinstall/install/postinstall script. */
  hasInstallScripts?: boolean;
  /** Latest version has a registry-verified provenance attestation (SLSA). */
  hasProvenance?: boolean;
  /** Latest version carries a deprecation notice. */
  isDeprecated?: boolean;
  /** Package metadata links a source repository. */
  hasRepository?: boolean;
}

/** Scoped names must keep a raw `@` with only the slash encoded
 *  (`@scope%2Fname`) — `%40scope%2Fname` is rejected by the npm registry. */
function npmUrlName(pkg: string): string {
  return pkg.startsWith("@")
    ? `@${encodeURIComponent(pkg.slice(1))}`
    : encodeURIComponent(pkg);
}

/**
 * Percent-encode each path SEGMENT while keeping the `/` separators that are
 * semantically required by Packagist (`vendor/name`) and the Go proxy
 * (`github.com/org/mod`) — the two registries whose names legitimately contain
 * slashes and so cannot be blanket-`encodeURIComponent`d.
 *
 * Defence in depth, not an SSRF fix: every registry host here is a hardcoded
 * literal and a package name only ever lands in the URL *path*, so it can never
 * redirect the request to another (e.g. internal) host — the authority is
 * already closed. This keeps a hostile package name (`@`, `?`, `#`, spaces,
 * control chars) from reshaping the request to the fixed registry, and keeps
 * the call clean to an automated URL/SSRF scanner. Transparent for real names:
 * `monolog/monolog` and `github.com/!azure/azure-sdk-for-go` are unchanged
 * (`encodeURIComponent` leaves `-._~!` alone).
 */
function encodePathSegments(p: string): string {
  return p.split("/").map(encodeURIComponent).join("/");
}

async function fetchNpm(pkg: string): Promise<RegistryResult> {
  const url = `https://registry.npmjs.org/${npmUrlName(pkg)}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (res.status === 404)
    return { exists: false, isNewPackage: false, publishedAt: null };
  if (!res.ok) throw new Error(`npm registry HTTP ${res.status}`);

  const data = (await res.json()) as any;
  // Unpublished stub (200 tombstone, empty versions map): nothing installable,
  // name re-claimable — report as non-existent, same as the server detector.
  if (Object.keys(data.versions ?? {}).length === 0 && data.time?.created) {
    return { exists: false, isNewPackage: false, publishedAt: null };
  }
  const firstVersionTime = data.time?.created
    ? new Date(data.time.created)
    : null;
  const isNewPackage = firstVersionTime
    ? Date.now() - firstVersionTime.getTime() < NEW_PACKAGE_WINDOW_MS
    : false;
  return {
    exists: true,
    isNewPackage,
    publishedAt: firstVersionTime,
    ...parseNpmTrustSignals(data),
  };
}

/** npm trust signals from the packument's latest version (no extra fetch). */
function parseNpmTrustSignals(
  data: any
): Pick<
  RegistryResult,
  "hasInstallScripts" | "hasProvenance" | "isDeprecated" | "hasRepository"
> {
  const latest = data["dist-tags"]?.latest
    ? data.versions?.[data["dist-tags"].latest]
    : null;
  const scripts = latest?.scripts ?? {};
  return {
    hasInstallScripts: !!(
      scripts.preinstall ||
      scripts.install ||
      scripts.postinstall
    ),
    hasProvenance: !!latest?.dist?.attestations,
    isDeprecated:
      typeof latest?.deprecated === "string" && latest.deprecated.length > 0,
    hasRepository: !!data.repository?.url,
  };
}

async function fetchPypi(pkg: string): Promise<RegistryResult> {
  const url = `https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (res.status === 404)
    return { exists: false, isNewPackage: false, publishedAt: null };
  if (!res.ok) throw new Error(`PyPI HTTP ${res.status}`);

  const data = (await res.json()) as any;
  const releases = data.releases ?? {};
  const allDates = Object.values(releases)
    .flat()
    .map((r: any) => r.upload_time)
    .filter(Boolean)
    .sort();
  const firstPublished = allDates.length
    ? new Date(allDates[0] as string)
    : null;
  const isNewPackage = firstPublished
    ? Date.now() - firstPublished.getTime() < NEW_PACKAGE_WINDOW_MS
    : false;
  return { exists: true, isNewPackage, publishedAt: firstPublished };
}

/** crates.io policy requires an identifying User-Agent — anonymous requests 403. */
const CRATES_UA = "graneth-core-checks (+https://graneth.com)";

async function fetchCrates(pkg: string): Promise<RegistryResult> {
  // crates.io treats `-` and `_` as interchangeable, so the name is queried
  // as written (verified live: serde_json and serde-json both resolve).
  const url = `https://crates.io/api/v1/crates/${encodeURIComponent(pkg)}`;
  const res = await fetch(url, {
    signal: AbortSignal.timeout(5000),
    headers: { "User-Agent": CRATES_UA },
  });
  if (res.status === 404)
    return { exists: false, isNewPackage: false, publishedAt: null };
  if (!res.ok) throw new Error(`crates.io HTTP ${res.status}`);

  const data = (await res.json()) as any;
  const created = data?.crate?.created_at
    ? new Date(data.crate.created_at)
    : null;
  const isNewPackage = created
    ? Date.now() - created.getTime() < NEW_PACKAGE_WINDOW_MS
    : false;
  return { exists: true, isNewPackage, publishedAt: created };
}

async function fetchGems(pkg: string): Promise<RegistryResult> {
  // The versions endpoint (newest first) gives 404-existence AND the true first
  // publish date — the gems/{name}.json endpoint only exposes the LATEST
  // version's date, which would misread any recently-updated old gem as "new".
  const url = `https://rubygems.org/api/v1/versions/${encodeURIComponent(pkg)}.json`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (res.status === 404)
    return { exists: false, isNewPackage: false, publishedAt: null };
  if (!res.ok) throw new Error(`rubygems HTTP ${res.status}`);

  const versions = (await res.json()) as any[];
  if (!Array.isArray(versions) || versions.length === 0) {
    return { exists: false, isNewPackage: false, publishedAt: null }; // yanked-empty: nothing installable
  }
  const dates = versions
    .map(v => v?.created_at)
    .filter(Boolean)
    .sort();
  const first = dates.length ? new Date(dates[0] as string) : null;
  const isNewPackage = first
    ? Date.now() - first.getTime() < NEW_PACKAGE_WINDOW_MS
    : false;
  return { exists: true, isNewPackage, publishedAt: first };
}

async function fetchComposer(pkg: string): Promise<RegistryResult> {
  // packagist.org/packages/{vendor}/{name}.json → package.time is the true
  // first-publish timestamp (verified live on monolog/monolog).
  const url = `https://packagist.org/packages/${encodePathSegments(pkg)}.json`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (res.status === 404)
    return { exists: false, isNewPackage: false, publishedAt: null };
  if (!res.ok) throw new Error(`packagist HTTP ${res.status}`);

  const data = (await res.json()) as any;
  const created = data?.package?.time ? new Date(data.package.time) : null;
  const isNewPackage = created
    ? Date.now() - created.getTime() < NEW_PACKAGE_WINDOW_MS
    : false;
  return { exists: true, isNewPackage, publishedAt: created };
}

/** Go proxy path escaping: uppercase letters become `!` + lowercase. */
export function goProxyEscape(modulePath: string): string {
  return modulePath.replace(/[A-Z]/g, c => `!${c.toLowerCase()}`);
}

async function fetchGoModule(pkg: string): Promise<RegistryResult> {
  // @latest → {Version, Time}. 404 AND 410 both mean "module not found"
  // (verified live; the proxy backend does a git ls-remote for cache misses,
  // which is slow for nonexistent modules — hence the longer timeout).
  const url = `https://proxy.golang.org/${encodePathSegments(goProxyEscape(pkg))}/@latest`;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (res.status === 404 || res.status === 410)
    return { exists: false, isNewPackage: false, publishedAt: null };
  if (!res.ok) throw new Error(`go proxy HTTP ${res.status}`);
  await res.json(); // shape check only — Time is the LATEST version, not first publish
  // First-publish date isn't available in one call, so isNewPackage stays false
  // (honest: the new-module window signal is simply not offered for Go).
  return { exists: true, isNewPackage: false, publishedAt: null };
}

const REGISTRY_CLIENTS: Record<
  Ecosystem,
  (pkg: string) => Promise<RegistryResult>
> = {
  npm: fetchNpm,
  pypi: fetchPypi,
  crates: fetchCrates,
  gems: fetchGems,
  composer: fetchComposer,
  go: fetchGoModule,
};

/**
 * The registries the detector actually queries, as a RUNTIME value.
 *
 * `Ecosystem` is a type, so before this existed nothing outside the type system
 * could count the set — and anything that needed the count had to write a
 * number down. That is exactly what this exists to prevent: a count comes from
 * the source it describes, never from a literal somebody typed beside it and
 * then forgot when the set changed.
 *
 * Derived from the client table rather than listed beside it, so "the
 * ecosystems we check" and "the ecosystems we have a client for" cannot become
 * two facts. Adding a client adds it here; the `Ecosystem` annotation keeps the
 * pair exhaustive in the other direction.
 */
export const ECOSYSTEMS: readonly Ecosystem[] = Object.keys(
  REGISTRY_CLIENTS
) as Ecosystem[];

/**
 * Check whether a package exists in its registry. Fails open (exists:true,
 * unreachable:true) if the registry can't be reached, so a network blip never
 * blocks a commit on a false "does not exist".
 */
export async function packageExists(
  pkg: string,
  ecosystem: Ecosystem
): Promise<RegistryResult> {
  try {
    return await REGISTRY_CLIENTS[ecosystem](pkg);
  } catch {
    return {
      exists: true,
      isNewPackage: false,
      publishedAt: null,
      unreachable: true,
    };
  }
}
