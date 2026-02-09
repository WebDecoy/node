/**
 * Filter Rule
 * Implements the Rule interface using the filter expression language
 */

import { Parser, ASTNode } from './filter/parser';
import { evaluate } from './filter/evaluator';
import type { Rule, RuleContext, RuleResult, FilterConfig } from './types';

export class FilterRule implements Rule {
  readonly name: string;
  private ast: ASTNode;
  private action: 'DENY' | 'THROTTLE';
  private dryRun: boolean;
  private expression: string;

  constructor(config: FilterConfig) {
    this.expression = config.expression;
    this.action = config.action ?? 'DENY';
    this.dryRun = config.dryRun ?? false;
    this.name = `filter:${this.expression.slice(0, 50)}`;

    // Parse at construction time — fail fast on syntax errors
    const parser = new Parser(config.expression);
    this.ast = parser.parse();
  }

  evaluate(context: RuleContext): RuleResult {
    const result = evaluate(this.ast, context);

    // If the filter expression evaluates to truthy, the rule triggers
    if (result) {
      return {
        action: this.dryRun ? 'ALLOW' : this.action,
        rule: this.name,
        reason: `Filter matched: ${this.expression}`,
        metadata: {
          expression: this.expression,
          dryRun: this.dryRun,
        },
      };
    }

    return {
      action: 'ALLOW',
      rule: this.name,
    };
  }
}
