/**
 * GENERATED — do not edit by hand. Refresh with: node scripts/refresh-threat-snapshot.mjs
 * Snapshot of https://graneth.com/api/threat-feed (feed version 3).
 * Bundled into the free MCP so a known hallucinated name is caught INSTANTLY —
 * and, critically, KEEPS being caught after an attacker registers the package,
 * the moment a live existence check alone goes silent. No network call needed.
 *
 * The tier is the row's PROVENANCE, and the finding text quotes it back to the
 * user, so it may never claim more than the row's origin supports. `confirmed`
 * was retired on 2026-08-07: it had been stamped on every curated row
 * regardless of origin — including the names Graneth constructed from the
 * documented pattern, which the seed file calls "plausible targets, not
 * observations".
 * Snapshot taken: 2026-08-07 · entries: 38
 */
export interface ThreatSnapshotEntry { name: string; ecosystem: string; tier: "reported" | "pattern" | "observed" | "community"; recorded: string | null }
export const THREAT_SNAPSHOT: ThreatSnapshotEntry[] = [
  {
    "name": "flask-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "flask-gpt4",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "flask-chatgpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "django-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "django-ai",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "django-llm",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "fastapi-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "fastapi-chatgpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "express-gpt",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "express-ai",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "react-gpt",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "react-ai-helper",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "vue-gpt",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "next-gpt",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "next-ai",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "prisma-gpt",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "langchain-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "langchain-gpt4",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "openai-utils",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "gpt-utils",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "gpt-helper",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "ai-utils",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "llm-utils",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "llm-helper",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "chatgpt-helper",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "chatgpt-utils",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "mongoose-gpt",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "sequelize-ai",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "drizzle-ai",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "axios-ai",
    "ecosystem": "npm",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "pandas-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "numpy-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "pytorch-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "tensorflow-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "sklearn-gpt",
    "ecosystem": "pypi",
    "tier": "pattern",
    "recorded": "2026-06-01"
  },
  {
    "name": "react-codeshift",
    "ecosystem": "npm",
    "tier": "reported",
    "recorded": "2026-04-19"
  },
  {
    "name": "unused-imports",
    "ecosystem": "npm",
    "tier": "reported",
    "recorded": "2026-04-19"
  },
  {
    "name": "huggingface-cli",
    "ecosystem": "pypi",
    "tier": "reported",
    "recorded": "2026-04-19"
  }
];
