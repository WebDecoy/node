/**
 * Bot-category rule.
 *
 * The one-liner for the policy this product category exists to express:
 *
 * ```typescript
 * bots({ categories: ['training_crawler'] })   // no AI training on my content
 * ```
 *
 * This is expressible as a filter expression too — `bot.category ==
 * "training_crawler"` — and that is the right tool once the policy has
 * conditions. This exists because the common case should not require learning an
 * expression language, and because `allow` is fiddly to spell correctly by hand.
 *
 * WHAT IT CAN AND CANNOT SEE
 *
 * It matches on the User-Agent, so it only ever acts on agents that declare
 * themselves. That is sound for this policy — GPTBot and ClaudeBot identify
 * honestly, and the decision is about a cooperative agent's access, not about
 * catching a liar. Anything spoofing Chrome passes straight through, and the
 * tripwire and edge layers are what catch those.
 */

import type { Rule, RuleContext, RuleResult, BotRuleConfig } from './types';

export class BotRule implements Rule {
  readonly name = 'bots';
  private readonly categories: Set<string>;
  private readonly agents: Set<string>;
  private readonly ai: boolean;
  private readonly allow: Set<string>;
  private readonly action: 'DENY' | 'THROTTLE';
  private readonly dryRun: boolean;

  constructor(config: BotRuleConfig = {}) {
    this.categories = new Set(config.categories ?? []);
    // Slugs and display names are both accepted, because `'GPTBot'` is what a
    // customer reads in their dashboard and `'gptbot'` is what the registry
    // calls it. Requiring the right one would be a support ticket per install.
    this.agents = new Set((config.agents ?? []).map((a) => a.toLowerCase()));
    this.ai = config.ai ?? false;
    this.allow = new Set((config.allow ?? []).map((a) => a.toLowerCase()));
    this.action = config.action ?? 'DENY';
    this.dryRun = config.dryRun ?? false;
  }

  evaluate(context: RuleContext): RuleResult {
    const bot = context.bot;
    if (!bot?.known) return { action: 'ALLOW', rule: this.name };

    // Exemptions win over every other clause. A customer who writes
    // `allow: ['googlebot']` means it unconditionally — an SEO outage caused by
    // a rule they thought they had scoped is far more expensive than a scraper
    // getting through.
    const id = bot.id?.toLowerCase();
    const name = bot.name?.toLowerCase();
    if ((id && this.allow.has(id)) || (name && this.allow.has(name))) {
      return { action: 'ALLOW', rule: this.name };
    }

    const matched =
      (this.ai && bot.isAI) ||
      this.categories.has(bot.category) ||
      (id !== undefined && this.agents.has(id)) ||
      (name !== undefined && this.agents.has(name));

    if (!matched) return { action: 'ALLOW', rule: this.name };

    return {
      action: this.dryRun ? 'ALLOW' : this.action,
      rule: this.name,
      reason: `${bot.name ?? 'Bot'} (${bot.category}) matched a bot policy rule`,
      metadata: {
        bot: bot.id,
        botName: bot.name,
        category: bot.category,
        organization: bot.organization,
        dryRun: this.dryRun,
        // Deliberately not 100. The match is a self-declared User-Agent, and a
        // downstream consumer that treats this like a tripwire hit would be
        // wrong: a tripwire proves behaviour, this repeats a claim.
        confidence: 70,
      },
    };
  }
}
