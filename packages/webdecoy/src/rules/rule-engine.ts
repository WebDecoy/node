/**
 * Rule Engine
 * Evaluates rules in order — first DENY/THROTTLE wins
 */

import { Rule, RuleContext, RuleResult, RuleEngineResult, ViolationEvent } from './types';

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
        // Record violation
        violations.push({
          rule: result.rule,
          action: result.action,
          ip: context.ip,
          path: context.path,
          method: context.method,
          userAgent: context.userAgent,
          reason: result.reason,
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
