/**
 * Hardcoded-secret detection — Shannon entropy + known credential patterns.
 *
 * Framework-free and dependency-free so both the Graneth server
 * (server/governance/advancedAnalyzer.ts) and the standalone
 * @graneth/mcp-server can share the exact same detection logic and never drift.
 */

// ─── Shannon entropy ──────────────────────────────────────────────────────────

/**
 * Compute Shannon entropy H(X) = -Σ P(xi) log₂ P(xi) for a string.
 * Pure random base64 ≈ 6 bits/char; typical passwords ≈ 4–5; prose ≈ 3–4.
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  Array.from(freq.values()).forEach((count) => {
    const p = count / str.length;
    h -= p * Math.log2(p);
  });
  return h;
}

export const MIN_SECRET_LENGTH = 20;
export const MAX_SECRET_LENGTH = 200;

// Per-charset entropy thresholds (bits/char).
// Hex alphabet has 4 bits max theoretical entropy, so a lower threshold is correct.
// Base64 alphabet has ~6 bits max; random printable ASCII can reach ~6.5.
export type Charset = "hex" | "base64" | "random";

export interface CharsetResult {
  charset: Charset;
  threshold: number; // minimum entropy to flag
  /** Maximum achievable bits/char for this alphabet — the normalization
   *  ceiling for the confidence score (hex: log2(16), base64: log2(64),
   *  random printable ASCII: ~log2(95)). */
  max: number;
}

export function detectCharset(str: string): CharsetResult {
  if (/^[0-9a-fA-F]+$/.test(str))        return { charset: "hex",    threshold: 3.8, max: 4 };
  if (/^[A-Za-z0-9+/=_-]+$/.test(str))   return { charset: "base64", threshold: 4.5, max: 6 };
  return                                           { charset: "random", threshold: 5.5, max: 6.6 };
}

// Variable-name keywords that strongly suggest a secret context.
// Matching ANY of these alongside a high-entropy value → high confidence.
export const SEMANTIC_SECRET_KEYWORDS = [
  "password", "passwd", "pwd", "pass",
  "secret", "private",
  "api_key", "apikey", "api-key",
  "access_key", "accesskey", "access-key",
  "auth_token", "authtoken",
  "access_token", "accesstoken",
  "bearer", "jwt", "signing_key",
  "private_key", "privatekey",
  "aws_access", "aws_secret",
  "client_secret", "client_id",
  "encryption_key", "enc_key",
  "database_url", "db_pass", "db_password",
  "stripe_key", "stripe_secret",
  "webhook_secret",
];

/**
 * Extract the variable/key name from the line (left-hand side of assignment).
 * Returns lower-case string or empty string if not found.
 */
export function extractVarName(line: string): string {
  // JS/TS: const FOO = / let FOO = / var FOO =
  const jsVar = line.match(/(?:const|let|var)\s+([A-Z_a-z][A-Z_a-z0-9]*)\s*=/i);
  if (jsVar) return jsVar[1].toLowerCase();
  // Python / env file: FOO = / FOO:
  const pyVar = line.match(/^[ \t]*([A-Z_a-z][A-Z_a-z0-9]*)\s*[=:]/);
  if (pyVar) return pyVar[1].toLowerCase();
  // JSON / YAML key: "key": or key:
  const jsonKey = line.match(/["']?([A-Z_a-z][A-Z_a-z0-9]*)["']?\s*:/i);
  if (jsonKey) return jsonKey[1].toLowerCase();
  return "";
}

/**
 * Confidence score combining entropy strength and semantic context.
 *
 * confidence = clamp(entropyScore × 0.55 + semanticBoost × 0.45, 0.50, 0.99)
 *
 * entropyScore: position within the ACHIEVABLE band for the detected charset,
 * (entropy − threshold) / (charset max − threshold), clamped to 0–1. The old
 * normalization (2× threshold) put a score of 1.0 above the theoretical
 * maximum entropy of every alphabet, which made the ≥0.8 "critical" severity
 * band mathematically unreachable — found by mutation testing, confirmed by
 * arithmetic, fixed here.
 * semanticBoost: 1.0 if the variable name matches a secret keyword, else 0.0.
 */
export function computeConfidence(entropy: number, cs: CharsetResult, varName: string): number {
  const entropyScore = Math.min(1, Math.max(0, (entropy - cs.threshold) / (cs.max - cs.threshold)));
  const semanticBoost = SEMANTIC_SECRET_KEYWORDS.some(kw => varName.includes(kw)) ? 1.0 : 0.0;
  const raw = entropyScore * 0.55 + semanticBoost * 0.45;
  return Math.min(0.99, Math.max(0.50, raw));
}

export interface SecretCandidate {
  value: string;
  context: string;
  varName: string;
}

/** Pull candidate strings from a single line of source code. */
export function extractSecretCandidates(line: string): SecretCandidate[] {
  const results: SecretCandidate[] = [];
  const varName = extractVarName(line);

  // String literals (single, double, backtick)
  const literalRe = /["'`]([^"'`\n]{20,200})["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = literalRe.exec(line)) !== null) {
    results.push({ value: m[1], context: line.trim(), varName });
  }
  // Bare value after common secret key names: password = abc123...
  const bareAssign = line.match(
    /(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[=:]\s*([^\s"'`,;#]{8,})/i
  );
  if (bareAssign) results.push({ value: bareAssign[1], context: line.trim(), varName });
  return results;
}

// ─── Known credential patterns (high-confidence, no entropy check needed) ────

export const KNOWN_SECRET_PATTERNS: Array<{
  pattern: RegExp;
  title: string;
  description: string;
  cve: string;
}> = [
  {
    pattern: /AKIA[0-9A-Z]{16}/,
    title: "AWS Access Key ID detected",
    description: "An AWS Access Key ID (AKIA…) was found in added code. This credential grants direct access to AWS services.",
    cve: "CWE-798",
  },
  {
    pattern: /(?:ghp|ghs|gho|ghu|github_pat)_[A-Za-z0-9_]{20,}/,
    title: "GitHub personal access token detected",
    description: "A GitHub token (ghp_/ghs_/ghu_/github_pat_) was found in added code.",
    cve: "CWE-798",
  },
  {
    pattern: /sk-[A-Za-z0-9]{20,}/,
    title: "API key with sk- prefix detected",
    description: "A secret key (sk-…) was found — commonly OpenAI, Stripe, or other service credentials.",
    cve: "CWE-798",
  },
  {
    // Modern hyphenated formats escape the legacy sk- pattern (the hyphen
    // breaks [A-Za-z0-9]{20,}) — found by dogfooding. The documented vendor
    // prefix segment keeps kebab-case identifiers (CSS classes etc.) out.
    pattern: /sk-(?:proj|svcacct|admin|ant)-[A-Za-z0-9_-]{20,}/,
    title: "OpenAI / Anthropic API key detected",
    description: "A modern secret key (sk-proj-… / sk-svcacct-… / sk-admin-… / sk-ant-…) was found — OpenAI project or Anthropic API credentials.",
    cve: "CWE-798",
  },
  {
    pattern: /[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/,
    title: "Stripe secret key detected",
    description: "A Stripe secret or restricted key (sk_live_/sk_test_/rk_live_) was found in added code. Live keys grant direct access to payment operations.",
    cve: "CWE-798",
  },
  {
    pattern: /xox[bpars]-[0-9A-Za-z-]{10,}/,
    title: "Slack token detected",
    description: "A Slack API token (xoxb-/xoxp-/xoxa-) was found in added code.",
    cve: "CWE-798",
  },
  {
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    title: "Private key block detected",
    description: "A PEM private key header was found in the diff. Private keys must never be committed.",
    cve: "CWE-321",
  },
];

/**
 * Credentials published verbatim in vendor documentation (AWS docs sample
 * keys). Real-shaped but grant nothing — callers downgrade a match to a
 * warning instead of a commit-blocking critical. Never silenced entirely.
 */
export const EXAMPLE_CREDENTIALS: ReadonlySet<string> = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "AKIAI44QH8DHBEXAMPLE",
  "wJalrXutnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
]);
