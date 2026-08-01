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

const INDEX = new Map<string, ThreatSnapshotEntry>(
  THREAT_SNAPSHOT.map((e) => [`${e.name.toLowerCase()}::${e.ecosystem}`, e]),
);

/** Snapshot entry for the name in this ecosystem, or null when unlisted. */
export function knownHallucination(pkg: string, ecosystem: string): ThreatSnapshotEntry | null {
  return INDEX.get(`${pkg.toLowerCase()}::${ecosystem}`) ?? null;
}
