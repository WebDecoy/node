/**
 * Tripwire Rule (F4 — deception layer)
 *
 * Deterministic, zero-false-positive bot detection: a request for a hidden
 * honeypot path (a "tripwire") that a real user can never reach — because it is
 * only exposed as an invisible link, listed in robots.txt `Disallow`, or is a
 * scanner-bait path no human ever types — is, by construction, automated.
 *
 * Unlike fingerprinting (which a stealth tool like botasaurus is purpose-built
 * to defeat), a tripwire detects *intent* — going where a human cannot — which
 * cannot be spoofed away by a better browser fingerprint.
 *
 * Implemented as a {@link Rule} so it flows through the existing
 * DENY -> block -> violation-report pipeline with no middleware changes.
 */

import type { Rule, RuleContext, RuleResult, TripwireConfig } from './types';

/**
 * Common scanner/scraper bait paths that no legitimate user ever requests.
 * Requesting any of these is a strong automated-intent signal on its own.
 */
export const DEFAULT_TRIPWIRE_PATHS: readonly string[] = [
  '/.git/config',
  '/.git/HEAD',
  '/.env',
  '/.env.local',
  '/.env.production',
  '/wp-config.php',
  '/config.php',
  '/.aws/credentials',
  '/.ssh/id_rsa',
  '/backup.zip',
  '/backup.sql',
  '/database.sql',
  '/dump.sql',
  '/.DS_Store',
  '/phpinfo.php',
  '/server-status',
  '/actuator/env',
  '/.vscode/sftp.json',
];

/**
 * Canonicalize a request path before matching a hidden-path tripwire.
 *
 * A scanner probing for `/.env` or `/.git/config` can dress the path up —
 * `//.env`, `/x/..%2f.git/config`, `/%2Eenv` — and a webserver still resolves it
 * to the file it was hunting for. Matching the raw string would miss the scan,
 * which is the one thing a tripwire exists to catch. So the query and fragment
 * are dropped and the path is reduced the way a server would: percent-decode
 * ASCII bytes, collapse duplicate slashes, and resolve `.` and `..` segments,
 * keeping a single trailing slash.
 */
export function canonicalizeTripwirePath(path: string): string {
  const noQuery = path.split('?')[0].split('#')[0];
  return cleanSlashesAndDots(decodePercentAscii(noQuery));
}

function decodePercentAscii(s: string): string {
  // Bounded, so a double-encoded separator (`%252F` -> `%2F` -> `/`) resolves
  // without unbounded work. ASCII bytes only: high bytes stay encoded rather
  // than risk throwing (decodeURIComponent) on invalid UTF-8.
  for (let i = 0; i < 4; i++) {
    const next = decodePercentAsciiOnce(s);
    if (next === s) break;
    s = next;
  }
  return s;
}

function decodePercentAsciiOnce(s: string): string {
  if (!s.includes('%')) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%' && i + 2 < s.length) {
      const hi = unhexNibble(s.charCodeAt(i + 1));
      const lo = unhexNibble(s.charCodeAt(i + 2));
      if (hi >= 0 && lo >= 0) {
        const v = (hi << 4) | lo;
        if (v < 0x80) {
          out += String.fromCharCode(v);
          i += 2;
          continue;
        }
      }
    }
    out += s[i];
  }
  return out;
}

function unhexNibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48; // 0-9
  if (c >= 97 && c <= 102) return c - 97 + 10; // a-f
  if (c >= 65 && c <= 70) return c - 65 + 10; // A-F
  return -1;
}

function cleanSlashesAndDots(s: string): string {
  if (s === '') return s;
  const hadTrailing = s.length > 1 && s[s.length - 1] === '/';
  const stack: string[] = [];
  for (const p of s.split('/')) {
    if (p === '' || p === '.') continue;
    if (p === '..') {
      if (stack.length > 0) stack.pop();
      continue;
    }
    stack.push(p);
  }
  let res = '/' + stack.join('/');
  if (hadTrailing && res !== '/') res += '/';
  return res;
}

export class TripwireRule implements Rule {
  readonly name = 'tripwire';
  private readonly exact: Set<string>;
  private readonly prefixes: string[];
  private readonly patterns: RegExp[];
  private readonly action: 'DENY' | 'THROTTLE';
  private readonly dryRun: boolean;

  constructor(config: TripwireConfig = {}) {
    const paths = [...(config.paths ?? [])];
    if (config.includeDefaults ?? true) paths.push(...DEFAULT_TRIPWIRE_PATHS);
    // Canonicalize the configured paths too, so both sides of the match are
    // reduced the same way and a decoy written as `/foo/../bar` still lines up.
    this.exact = new Set(paths.map(canonicalizeTripwirePath));
    this.prefixes = (config.prefixes ?? []).map(canonicalizeTripwirePath);
    this.patterns = config.patterns ?? [];
    this.action = config.action ?? 'DENY';
    this.dryRun = config.dryRun ?? false;
  }

  evaluate(context: RuleContext): RuleResult {
    const path = canonicalizeTripwirePath(context.path);
    const hit =
      this.exact.has(path) ||
      this.prefixes.some((prefix) => path.startsWith(prefix)) ||
      this.patterns.some((re) => re.test(path));

    if (hit) {
      return {
        action: this.dryRun ? 'ALLOW' : this.action,
        rule: this.name,
        reason: `Tripwire hit: ${path} — hidden honeypot path, deterministic automated-intent signal`,
        metadata: { path, dryRun: this.dryRun, confidence: 100 },
      };
    }

    return { action: 'ALLOW', rule: this.name };
  }
}
