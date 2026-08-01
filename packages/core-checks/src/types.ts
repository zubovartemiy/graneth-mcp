/** Shared, framework-free finding shape used by the core checks. */
export interface CoreFinding {
  type: string;
  severity: "critical" | "warning" | "info";
  title: string;
  description: string;
  file: string;
  line: number;
  recommendation?: string;
  cve?: string;
}

/**
 * Registries the detector verifies against. IDs are ≤8 chars on purpose —
 * the server's packageRegistryCache.ecosystem column is varchar(8).
 *  npm      — registry.npmjs.org
 *  pypi     — pypi.org
 *  crates   — crates.io (Rust)
 *  gems     — rubygems.org (Ruby; manifest-only extraction)
 *  go       — proxy.golang.org (Go modules)
 *  composer — packagist.org (PHP; manifest-only extraction)
 */
export type Ecosystem = "npm" | "pypi" | "crates" | "gems" | "go" | "composer";
