/**
 * Hardcoded-secret detection — Shannon entropy + known credential patterns.
 *
 * Framework-free and dependency-free so both the Graneth server
 * (server/governance/detection/advancedAnalyzer.ts) and the standalone
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
  Array.from(freq.values()).forEach(count => {
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
  if (/^[0-9a-fA-F]+$/.test(str))
    return { charset: "hex", threshold: 3.8, max: 4 };
  if (/^[A-Za-z0-9+/=_-]+$/.test(str))
    return { charset: "base64", threshold: 4.5, max: 6 };
  return { charset: "random", threshold: 5.5, max: 6.6 };
}

// Variable-name keywords that strongly suggest a secret context.
// Matching ANY of these alongside a high-entropy value → high confidence.
export const SEMANTIC_SECRET_KEYWORDS = [
  "password",
  "passwd",
  "pwd",
  "pass",
  "secret",
  "private",
  "api_key",
  "apikey",
  "api-key",
  "access_key",
  "accesskey",
  "access-key",
  "auth_token",
  "authtoken",
  "access_token",
  "accesstoken",
  "bearer",
  "jwt",
  "signing_key",
  "private_key",
  "privatekey",
  "aws_access",
  "aws_secret",
  "client_secret",
  "client_id",
  "encryption_key",
  "enc_key",
  "database_url",
  "db_pass",
  "db_password",
  "stripe_key",
  "stripe_secret",
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
export function computeConfidence(
  entropy: number,
  cs: CharsetResult,
  varName: string
): number {
  const entropyScore = Math.min(
    1,
    Math.max(0, (entropy - cs.threshold) / (cs.max - cs.threshold))
  );
  const semanticBoost = SEMANTIC_SECRET_KEYWORDS.some(kw =>
    varName.includes(kw)
  )
    ? 1.0
    : 0.0;
  const raw = entropyScore * 0.55 + semanticBoost * 0.45;
  return Math.min(0.99, Math.max(0.5, raw));
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
    // The trailing `[A-Za-z0-9_.-]*` makes `.env` keys reachable: the keyword is
    // rarely the end of the name (`SUPABASE_SERVICE_ROLE_KEY=`).
    /(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|service[_-]?role|database[_-]?url|conn(?:ection)?[_-]?string|credentials?)[A-Za-z0-9_.-]*\s*[=:]\s*([^\s"'`,;#]{8,})/i
  );
  if (bareAssign)
    results.push({ value: bareAssign[1], context: line.trim(), varName });
  return results;
}

// ─── Structured credentials the entropy path could never reach ───────────────

/**
 * Decode a JWT's payload without a JWT library.
 *
 * Returns null unless the token is three segments and the middle one decodes to
 * a JSON object. Deliberately does NOT verify the signature: the question here
 * is what a committed token CLAIMS to be, not whether it is currently valid.
 */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Roles whose bearer token is meant to be public.
 *
 * Supabase publishes the `anon` key in the client bundle by design — every
 * Next.js app built on it ships one, and flagging it would put a
 * commit-blocking critical on correct code. `service_role` is the opposite: it
 * bypasses every row level security policy in the project.
 */
export const PUBLIC_JWT_ROLES: ReadonlySet<string> = new Set([
  "anon",
  "public",
]);

/**
 * True only when the token provably carries a public role. Anything
 * undecodable, or carrying a role this does not know, fails closed.
 */
export function isPublicJwt(token: string): boolean {
  const payload = jwtPayload(token);
  if (!payload) return false;
  const role = payload.role;
  return typeof role === "string" && PUBLIC_JWT_ROLES.has(role);
}

/**
 * The full "this token is not a leak" test used by the pattern.
 *
 * Three ways a JWT in a diff is not a credential: it carries a public role; it
 * is the sample token from jwt.io, which is the most-copied JWT in existence
 * and appears in a great many READMEs and tutorials; or it has already expired,
 * in which case it grants nothing and cannot justify telling someone to rotate
 * a credential immediately.
 */
export function isNonSecretJwt(token: string): boolean {
  const payload = jwtPayload(token);
  if (!payload) return false;

  const role = payload.role;
  if (typeof role === "string" && PUBLIC_JWT_ROLES.has(role)) return true;

  // The jwt.io landing-page token, signed with the literal `your-256-bit-secret`.
  if (payload.sub === "1234567890" && payload.name === "John Doe") return true;

  const exp = payload.exp;
  if (typeof exp === "number" && Number.isFinite(exp)) {
    if (exp * 1000 < Date.now()) return true;
  }
  return false;
}

/**
 * Passwords that appear in documentation rather than in production.
 *
 * Exact values only — the SHAPE test below carries the general cases. Kept
 * short deliberately: the host check already clears every local and
 * container-service URI, so this list only has to cover a placeholder pointed
 * at a real hostname.
 */
export const PLACEHOLDER_PASSWORDS: ReadonlySet<string> = new Set([
  "pass",
  "passwd",
  "pwd",
  "postgres",
  "mysql",
  "mongo",
  "root",
  "admin",
  "guest",
  "user",
  "username",
  "stub",
  "probe",
  "test",
  "example",
  "changeme",
  "changeit",
  "apppass",
  "redacted",
  "dummy",
  "fake",
]);

/**
 * Placeholder SHAPES — `YOUR_PASSWORD_HERE`, `my-secret-pw`, `password123` and
 * the like, which no exact word list keeps up with.
 */
const PLACEHOLDER_SHAPE =
  /^(?:your[-_]?|my[-_]?|the[-_]?)?(?:pass(?:word)?|secret|pwd|creds?|key)(?:[-_]?(?:here|goes[-_]?here|123|pw|xxx+))?$/i;

/** A single character repeated at length — `xxxxxxxx`, `********`. */
const REPEATED_RUN = /^(.)\1{7,}$/;

/**
 * A password that IS a template expression, whole and entire.
 *
 * Whole-token deliberately: percent-encoding is mandatory in a URI userinfo
 * holding a reserved character, so merely CONTAINING `%` or `$` says nothing.
 */
const INTERPOLATION =
  /^(?:\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_]\w*|<[^>]*>|\[[^\]]*\]|\{\{[^}]*\}\}|%[A-Za-z_]\w*%)$/;

function isPlaceholderPassword(password: string): boolean {
  const candidates = [password];
  try {
    const decoded = decodeURIComponent(password);
    if (decoded !== password) candidates.push(decoded);
  } catch {
    // A malformed percent-escape is not a placeholder; judge the raw value.
  }
  return candidates.some(
    v =>
      PLACEHOLDER_PASSWORDS.has(v.toLowerCase()) ||
      PLACEHOLDER_SHAPE.test(v) ||
      REPEATED_RUN.test(v)
  );
}

// Username may be EMPTY: `redis://:password@host` is the canonical Redis form.
// The host alternation keeps a bracketed IPv6 literal intact.
const CONNECTION_URI_PARTS =
  /^(?:[a-z][a-z0-9+.-]*):\/\/([^\s:/@]*):([^\s/@]+)@(\[[^\]]+\]|[A-Za-z0-9._-]+)/i;

/**
 * True when a matched connection string is provably not a leaked credential:
 * the password is a whole template expression, or a documented placeholder, or
 * the host is not reachable from anywhere else.
 *
 * Anything it cannot parse stays a finding. This is a suppression, so its
 * failure direction is the opposite of `isNonSecretJwt`'s.
 */
export function isNonSecretConnectionUri(uri: string): boolean {
  const m = uri.match(CONNECTION_URI_PARTS);
  if (!m) return false;
  const password = m[2];
  const host = m[3].toLowerCase();

  // The host alphabet is ASCII, so a non-ASCII hostname would capture only its
  // leading label and then read as a single-label service name. If the capture
  // does not end at a delimiter, the host is not understood — keep the finding.
  const after = uri.slice(m[0].length);
  if (after !== "" && !/^[:/?#]/.test(after)) return false;

  if (INTERPOLATION.test(password)) return true;
  if (isPlaceholderPassword(password)) return true;

  // A bracketed IPv6 literal is an address, not a name: only loopback clears.
  if (host.startsWith("[")) {
    const ip = host.slice(1, -1);
    return ip === "::1" || ip === "::ffff:127.0.0.1";
  }

  if (host === "localhost" || host === "::1" || host === "0.0.0.0") return true;
  if (/^127\.\d+\.\d+\.\d+$/.test(host)) return true;
  // A single-label name is a container service, not a host on the internet.
  // Colons are excluded so a bare IPv6 can never fall through to this.
  if (!host.includes(".") && !host.includes(":")) return true;

  return false;
}

// ─── Known credential patterns (high-confidence, no entropy check needed) ────

export interface KnownSecretPattern {
  pattern: RegExp;
  title: string;
  description: string;
  cve: string;
  /**
   * Optional refinement, consulted with the matched text. Returning true drops
   * that match entirely — for shapes whose safe form is genuinely not a
   * credential, such as a published anon key or a localhost URI.
   *
   * Reach it through `firstRealMatch`, never by calling it directly.
   */
  notASecret?: (match: string) => boolean;
  /**
   * Severity when this pattern matches and survives its refinement. Defaults to
   * `critical`. `warning` is for a shape worth surfacing that must not block a
   * commit — a credential whose privilege cannot be judged from the line alone.
   */
  severity?: "critical" | "warning";
}

/**
 * The first occurrence in `content` that the pattern's refinement does NOT
 * clear, or null when every occurrence is cleared.
 *
 * EVERY consumer of `KNOWN_SECRET_PATTERNS` must go through this rather than
 * `content.match`, which returns only the first occurrence — a cleared match
 * would otherwise hide a real credential later on the same line.
 *
 * A fresh RegExp per call, so a global pattern's `lastIndex` never carries over.
 */
export function allMatches(
  content: string,
  p: Pick<KnownSecretPattern, "pattern">
): string[] {
  // A fresh RegExp per call, and the sticky flag dropped: `y` anchors the scan
  // at lastIndex and would find nothing past the first character.
  const flags = p.pattern.flags.replace(/[gy]/g, "") + "g";
  return Array.from(
    content.matchAll(new RegExp(p.pattern.source, flags)),
    m => m[0]
  );
}

export function firstRealMatch(
  content: string,
  p: Pick<KnownSecretPattern, "pattern" | "notASecret">
): string | null {
  return allMatches(content, p).find(m => !p.notASecret?.(m)) ?? null;
}

/**
 * The occurrences worth reporting, in order, with the ones a caller may treat
 * as harmless still present — a caller that needs to prefer one occurrence over
 * another has to see them all.
 */
export function realMatches(
  content: string,
  p: Pick<KnownSecretPattern, "pattern" | "notASecret">
): string[] {
  return allMatches(content, p).filter(m => !p.notASecret?.(m));
}

export const KNOWN_SECRET_PATTERNS: KnownSecretPattern[] = [
  {
    pattern: /AKIA[0-9A-Z]{16}/,
    title: "AWS Access Key ID detected",
    description:
      "An AWS Access Key ID (AKIA…) was found in added code. This credential grants direct access to AWS services.",
    cve: "CWE-798",
  },
  {
    pattern: /(?:ghp|ghs|gho|ghu|github_pat)_[A-Za-z0-9_]{20,}/,
    title: "GitHub personal access token detected",
    description:
      "A GitHub token (ghp_/ghs_/ghu_/github_pat_) was found in added code.",
    cve: "CWE-798",
  },
  {
    pattern: /sk-[A-Za-z0-9]{20,}/,
    title: "API key with sk- prefix detected",
    description:
      "A secret key (sk-…) was found — commonly OpenAI, Stripe, or other service credentials.",
    cve: "CWE-798",
  },
  {
    // Modern hyphenated formats escape the legacy sk- pattern (the hyphen
    // breaks [A-Za-z0-9]{20,}) — found by dogfooding. The documented vendor
    // prefix segment keeps kebab-case identifiers (CSS classes etc.) out.
    pattern: /sk-(?:proj|svcacct|admin|ant)-[A-Za-z0-9_-]{20,}/,
    title: "OpenAI / Anthropic API key detected",
    description:
      "A modern secret key (sk-proj-… / sk-svcacct-… / sk-admin-… / sk-ant-…) was found — OpenAI project or Anthropic API credentials.",
    cve: "CWE-798",
  },
  {
    pattern: /[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/,
    title: "Stripe secret key detected",
    description:
      "A Stripe secret or restricted key (sk_live_/sk_test_/rk_live_) was found in added code. Live keys grant direct access to payment operations.",
    cve: "CWE-798",
  },
  {
    pattern: /xox[bpars]-[0-9A-Za-z-]{10,}/,
    title: "Slack token detected",
    description:
      "A Slack API token (xoxb-/xoxp-/xoxa-) was found in added code.",
    cve: "CWE-798",
  },
  {
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    title: "Private key block detected",
    description:
      "A PEM private key header was found in the diff. Private keys must never be committed.",
    cve: "CWE-321",
  },
  {
    // Three base64url segments whose first two start `eyJ` — the encoding of
    // `{"`. Matched by shape: a real service_role token exceeds
    // MAX_SECRET_LENGTH, so the entropy path never measures one.
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    title: "Hardcoded JSON Web Token detected",
    description:
      "A JSON Web Token was found in added code. A Supabase `service_role` token bypasses every row level security policy in the project, and any long-lived bearer token grants whatever its claims allow until it expires.",
    cve: "CWE-798",
    notASecret: isNonSecretJwt,
  },
  {
    // Any scheme, matching `CONNECTION_URI_PARTS` and `redact.ts` — a fixed
    // list misses `dialect+driver://` (SQLAlchemy) and `mysql2://` (Rails).
    // Requires `user:password@`: a URI with no credentials, or a username
    // only, is configuration and not a leak.
    pattern:
      /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]*:[^\s/@]+@(?:\[[^\]]+\]|[A-Za-z0-9._-]+)/i,
    title: "Database connection string with embedded password detected",
    description:
      "A database URI carrying its own password was found in added code. The credential travels wherever the string does — into logs, error reports, and the repository's history.",
    cve: "CWE-798",
    notASecret: isNonSecretConnectionUri,
  },
  {
    // A lookahead rather than `\b`: a key may end in `-`, where a following
    // quote leaves no word boundary. The lookahead still refuses to match a
    // prefix of something longer.
    pattern: /\bAIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/,
    title: "Google API key detected",
    description:
      "A Google API key (AIza…) was found in added code. Unless it carries an application restriction, anyone holding it can spend against the project's quota.",
    cve: "CWE-798",
    // Firebase's web `apiKey` is an AIza key that Google documents as safe to
    // ship in client code. Restriction status is not readable from the line, so
    // this surfaces without blocking.
    severity: "warning",
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
