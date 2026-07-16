/**
 * Rule Engine
 * Evaluates rules in order — first DENY/THROTTLE wins
 */

import { Rule, RuleContext, RuleResult, RuleEngineResult, ViolationEvent } from './types';

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
   * Evaluate all rules against the request context.
   * First DENY or THROTTLE result wins. Violations are recorded for all non-ALLOW results.
   */
  evaluate(context: RuleContext): RuleEngineResult {
    const violations: ViolationEvent[] = [];
    let decidingResult: RuleResult | null = null;

    for (const rule of this.rules) {
      const result = rule.evaluate(context);

      if (result.action !== 'ALLOW') {
        // Record violation. Tripwire hits (a real user can't reach a honeypot
        // path) carry the actor's wd_clearance token so the backend can deny its
        // device fingerprint — the deception signal driving enforcement (#136).
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
          dryRun: result.metadata?.dryRun === true,
          timestamp: new Date(context.timestamp).toISOString(),
        });

        // First non-ALLOW result that is not dry-run decides the outcome
        if (!decidingResult && !result.metadata?.dryRun) {
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
      };
    }

    return {
      action: 'ALLOW',
      violations,
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
