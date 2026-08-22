/**
 * Rule Engine
 * Evaluates rules in order — first DENY/THROTTLE wins
 */

import { Rule, RuleContext, RuleResult, RuleEngineResult, ViolationEvent } from './types';
import type { RuleOutcome } from '../decision';

/** Pull the wd_clearance token from a request's Cookie header, if present. */
function extractClearance(headers: Record<string, string>): string | undefined {
  const cookie = headers['cookie'];
  if (!cookie) return undefined;
  for (const part of cookie.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === 'wd_clearance') {
      return part.slice(eq + 1).trim() || undefined;
    }
  }
  return undefined;
}

export class RuleEngine {
  private rules: Rule[];

  constructor(rules: Rule[]) {
    this.rules = rules;
  }

  /**
   * Append a rule after construction.
   *
   * Exists for signals that cannot be known synchronously at construction —
   * currently the site honeytoken, whose path is derived by async HMAC.
   * Evaluation order is append order, matching the constructor.
   */
  add(rule: Rule): void {
    this.rules.push(rule);
  }

  /**
   * Evaluate all rules against the request context.
   * First DENY or THROTTLE result wins. Violations are recorded for all non-ALLOW results.
   */
  evaluate(context: RuleContext): RuleEngineResult {
    const violations: ViolationEvent[] = [];
    const results: RuleOutcome[] = [];
    let decidingResult: RuleResult | null = null;

    for (const rule of this.rules) {
      const result = rule.evaluate(context);
      const dryRun = result.metadata?.dryRun === true;

      // Recorded for every rule, not only the ones that fired. A rule that
      // allowed and a rule that never ran both used to leave no trace, and the
      // difference between them is the difference between "checked and fine"
      // and "never checked".
      //
      // A dry-run rule reports `action: 'ALLOW'` because it must not block, but
      // its conclusion is DENY — that is the whole point of watching it. Reading
      // the action alone would show every dry-run rule as passing, which is the
      // opposite of what the operator turned it on to see.
      results.push({
        rule: result.rule,
        state: result.state ?? (dryRun ? 'DRY_RUN' : 'RUN'),
        conclusion: dryRun || result.action !== 'ALLOW' ? 'DENY' : 'ALLOW',
        action: result.action,
        reason: result.reason,
        metadata: result.metadata,
      });

      if (result.action !== 'ALLOW') {
        // Record violation. Tripwire hits (a real user can't reach a honeypot
        // path) carry the actor's wd_clearance token so the backend can deny its
        // device fingerprint — the deception signal driving enforcement.
        violations.push({
          rule: result.rule,
          action: result.action,
          ip: context.ip,
          path: context.path,
          method: context.method,
          userAgent: context.userAgent,
          reason: result.reason,
          clearance: result.rule === 'tripwire' ? extractClearance(context.headers) : undefined,
          metadata: result.metadata,
          dryRun,
          timestamp: new Date(context.timestamp).toISOString(),
        });

        // First non-ALLOW result that is not dry-run decides the outcome
        if (!decidingResult && !dryRun) {
          decidingResult = result;
        }
      }
    }

    if (decidingResult) {
      return {
        action: decidingResult.action,
        rule: decidingResult.rule,
        reason: decidingResult.reason,
        metadata: decidingResult.metadata,
        violations,
        results,
      };
    }

    return {
      action: 'ALLOW',
      violations,
      results,
    };
  }

  /**
   * Clean up all rule resources
   */
  destroy(): void {
    for (const rule of this.rules) {
      rule.destroy?.();
    }
  }
}
