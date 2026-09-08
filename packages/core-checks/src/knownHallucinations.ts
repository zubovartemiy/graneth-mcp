/**
 * Lookup over the bundled threat-feed snapshot (threatSnapshot.ts, generated).
 *
 * Why this exists next to the live registry check: the two cover different
 * failure windows. The registry check catches a name the moment it does not
 * exist; this list keeps catching it AFTER an attacker registers the package —
 * the exact moment the existence check goes silent. Community reports flow in
 * through /api/threat-feed/report and ship to every user at the next publish.
 *
 * Local and synchronous by design: no network call, so the trust contract of
 * the free MCP ("registry lookups are the only automatic network calls") holds.
 */
import { THREAT_SNAPSHOT, type ThreatSnapshotEntry } from "./threatSnapshot.js";

/**
 * The key both the index and the lookup use.
 *
 * crates.io treats `_` and `-` as the same crate — the registry client says so
 * in its own comment — so an exact-string index meant a name reported as
 * `foo-gpt` never matched `use foo_gpt`, and the local list, whose whole point
 * is to keep catching a name after an attacker registers it, silently did not.
 * Applying the registry's own equivalence here keeps the two in step.
 */
function indexKey(name: string, ecosystem: string): string {
  const lower = name.toLowerCase();
  return `${ecosystem === "crates" ? lower.replace(/_/g, "-") : lower}::${ecosystem}`;
}

const INDEX = new Map<string, ThreatSnapshotEntry>(
  THREAT_SNAPSHOT.map(e => [indexKey(e.name, e.ecosystem), e])
);

/** Snapshot entry for the name in this ecosystem, or null when unlisted. */
export function knownHallucination(
  pkg: string,
  ecosystem: string
): ThreatSnapshotEntry | null {
  return INDEX.get(indexKey(pkg, ecosystem)) ?? null;
}
