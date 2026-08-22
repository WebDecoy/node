/**
 * Attack payloads in the request.
 *
 * WHAT THIS IS, AND WHAT IT REFUSES TO BE
 *
 * Tripwires catch scanners by the **path** they ask for. Nothing here looked at
 * what those same scanners *send* — the injection strings in a query, the
 * traversal in a parameter, the `${jndi:` in a header. Their absence read as
 * "this only does honeypots".
 *
 * This is not a WAF and should not grow into one. A WAF's value is breadth, and
 * breadth is bought with false positives on ordinary traffic — which is the
 * complaint every incumbent's customers have. What this is: a small, curated set
 * of signatures that are unambiguous, cheap, and useful precisely because they
 * compose with the deterministic signals. A request that carries an injection
 * payload *and* walks into a tripwire is a far stronger detection than either
 * alone, and both are facts rather than probabilities.
 *
 * FALSE POSITIVES ARE THE DESIGN CONSTRAINT
 *
 * By default only the path and query string are inspected. Bodies and headers
 * are opt-in, because a CMS saving an article, a template in a JSON payload and
 * a URL passed as a query parameter all legitimately contain things that look
 * like attacks. Inspecting them is the right call for an API that never carries
 * markup, and the wrong one for a publishing tool — so it is the operator's
 * call, and `dryRun` is the way to find out.
 *
 * PERFORMANCE IS ALSO A CONSTRAINT
 *
 * Every pattern is anchored or literal, with no nested quantifiers — a regex
 * that backtracks catastrophically on a crafted input turns a detection rule
 * into the denial of service it was meant to catch. Input is truncated before
 * matching, and decoded a bounded number of times.
 */

import type { Rule, RuleContext, RuleResult } from './types';

/** One signature: a name, what it looks for, and where it is worth looking. */
interface Signature {
  id: string;
  label: string;
  test: RegExp;
}

/**
 * The curated set.
 *
 * Each of these is a string that has no innocent reading in a URL path or query
 * — which is a much higher bar than "seen in an attack". `SELECT` alone is a
 * word; `UNION SELECT ... FROM` is not something a form posts by accident.
 */
const SIGNATURES: readonly Signature[] = [
  // --- SQL injection -------------------------------------------------------
  { id: 'sqli_union', label: 'SQL UNION SELECT', test: /\bunion\b[\s/*]+\bselect\b/i },
  {
    id: 'sqli_tautology',
    label: 'SQL tautology',
    // ' OR 1=1 / " or 'a'='a — the quote is required, which is what keeps this
    // off ordinary query strings containing "or".
    test: /['"`]\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|['"`][^'"`]{0,32}['"`]\s*=\s*['"`])/i,
  },
  {
    id: 'sqli_stacked',
    label: 'Stacked SQL statement',
    test: /;\s*(?:drop|truncate|alter|create|insert|update|delete)\s+(?:table|database|from|into)\b/i,
  },
  {
    id: 'sqli_timing',
    label: 'SQL timing function',
    test: /\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(/i,
  },
  { id: 'sqli_probe', label: 'SQL metadata probe', test: /\binformation_schema\.[a-z_]+/i },

  // --- Cross-site scripting -----------------------------------------------
  { id: 'xss_script_tag', label: 'Inline <script>', test: /<\s*script[\s>/]/i },
  { id: 'xss_javascript_uri', label: 'javascript: URI', test: /javascript\s*:[^\s]{0,64}\(/i },
  {
    id: 'xss_event_handler',
    label: 'Inline event handler',
    // Requires a tag context, so `onerror` as a bare parameter name is not a hit.
    test: /<[a-z][a-z0-9]{0,15}[^>]{0,256}\son(?:error|load|click|mouseover|focus)\s*=/i,
  },
  { id: 'xss_svg_onload', label: 'SVG onload', test: /<\s*svg[^>]{0,128}\bonload\b/i },

  // --- Path traversal ------------------------------------------------------
  {
    id: 'traversal',
    label: 'Path traversal',
    // Two or more segments: a single `../` shows up in legitimately relative
    // redirect targets often enough to be worth the extra evidence.
    test: /(?:\.\.[/\\]){2,}/,
  },
  { id: 'traversal_etc', label: 'Sensitive file path', test: /\/etc\/(?:passwd|shadow)\b/i },

  // --- Command injection ---------------------------------------------------
  {
    id: 'cmdi_shell',
    label: 'Shell command injection',
    test: /[;|&`]\s*(?:cat|curl|wget|nc|bash|sh|python|perl|chmod)\s+[-/\w]/i,
  },
  { id: 'cmdi_subshell', label: 'Shell substitution', test: /\$\([a-z][^)]{0,64}\)/i },

  // --- Template / expression injection -------------------------------------
  { id: 'ssti_jndi', label: 'JNDI lookup (Log4Shell)', test: /\$\{\s*jndi\s*:/i },
  { id: 'ssti_expression', label: 'Template expression', test: /\{\{\s*[\w.]+\s*[(*]/ },
];

export interface AttackSignatureConfig {
  /**
   * Which parts of the request to inspect.
   *
   * Defaults to `['path', 'query']`, which is where a signature has no innocent
   * reading. `'body'` and `'headers'` are opt-in: a CMS saving an article, a
   * template inside a JSON payload and a URL passed as a parameter all
   * legitimately contain things that look like attacks. Start those in `dryRun`.
   *
   * @default ['path', 'query']
   */
  inspect?: ('path' | 'query' | 'body' | 'headers')[];
  /**
   * Bytes of each inspected part to scan. Beyond this the input is truncated,
   * so a large body cannot turn matching into the denial of service the rule
   * exists to catch.
   * @default 8192
   */
  maxBytes?: number;
  /** Signature ids to skip, e.g. `['traversal']`. */
  exclude?: string[];
  /** Action on a match. @default 'DENY' */
  action?: 'DENY' | 'THROTTLE';
  /** Log the violation but do not block. */
  dryRun?: boolean;
}

/**
 * Decode percent-encoding, twice at most.
 *
 * Attacks arrive encoded, often doubly, and matching the raw string misses them.
 * Unbounded decoding is not the answer either: it is unclear what a
 * quadruple-encoded string even means, and each pass is work an attacker
 * controls the amount of.
 */
function decodeBounded(input: string): string[] {
  const forms = [input];
  let current = input;
  for (let i = 0; i < 2; i++) {
    if (!current.includes('%')) break;
    let next: string;
    try {
      next = decodeURIComponent(current);
    } catch {
      // Malformed encoding. Deliberately not a hit on its own — plenty of real
      // clients send stray percent signs — but nothing further to decode.
      break;
    }
    if (next === current) break;
    forms.push(next);
    current = next;
  }
  return forms;
}

export class AttackSignatureRule implements Rule {
  readonly name = 'attack-signatures';
  private readonly inspect: ReadonlySet<string>;
  private readonly maxBytes: number;
  private readonly signatures: readonly Signature[];
  private readonly action: 'DENY' | 'THROTTLE';
  private readonly dryRun: boolean;

  constructor(config: AttackSignatureConfig = {}) {
    this.inspect = new Set(config.inspect ?? ['path', 'query']);
    this.maxBytes = config.maxBytes ?? 8192;
    const excluded = new Set(config.exclude ?? []);
    this.signatures = SIGNATURES.filter((s) => !excluded.has(s.id));
    this.action = config.action ?? 'DENY';
    this.dryRun = config.dryRun ?? false;
  }

  evaluate(context: RuleContext): RuleResult {
    for (const [where, raw] of this.parts(context)) {
      if (!raw) continue;
      const truncated = raw.length > this.maxBytes ? raw.slice(0, this.maxBytes) : raw;
      for (const form of decodeBounded(truncated)) {
        for (const signature of this.signatures) {
          if (!signature.test.test(form)) continue;
          return {
            action: this.dryRun ? 'ALLOW' : this.action,
            rule: this.name,
            reason: `${signature.label} in request ${where}`,
            metadata: {
              signature: signature.id,
              label: signature.label,
              where,
              dryRun: this.dryRun,
            },
          };
        }
      }
    }

    return { action: 'ALLOW', rule: this.name };
  }

  private parts(context: RuleContext): [string, string | undefined][] {
    const out: [string, string | undefined][] = [];
    if (this.inspect.has('path')) out.push(['path', context.path]);
    if (this.inspect.has('query')) out.push(['query', context.query]);
    if (this.inspect.has('body')) out.push(['body', context.body]);
    if (this.inspect.has('headers')) {
      for (const [name, value] of Object.entries(context.headers ?? {})) {
        // Cookies are excluded: they carry opaque, application-defined values
        // that hit signatures by coincidence, and a session token that trips a
        // rule logs the user out for no reason anyone can explain.
        if (name === 'cookie') continue;
        out.push([`header:${name}`, value]);
      }
    }
    return out;
  }
}

/**
 * Deny requests carrying unambiguous attack payloads. See
 * {@link AttackSignatureConfig} — and note that this is a small curated set, not
 * a WAF.
 */
export function attackSignatures(config: AttackSignatureConfig = {}): Rule {
  return new AttackSignatureRule(config);
}

/** The signature ids, for `exclude` and for tests. */
export const ATTACK_SIGNATURE_IDS: readonly string[] = SIGNATURES.map((s) => s.id);
