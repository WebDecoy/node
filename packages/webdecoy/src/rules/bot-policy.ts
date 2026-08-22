/**
 * One bot policy, published and enforced.
 *
 * WHY THIS EXISTS
 *
 * `BOT_REGISTRY` is generated from the Go registry and already carries the
 * customer-facing categories. `bots()` enforces against that table. Nothing
 * published from it — so every site that wanted to control AI crawlers
 * hand-wrote a `robots.txt` that drifted from whatever the code actually did.
 *
 * Drift here is not cosmetic. A `robots.txt` that disallows GPTBot while the
 * middleware lets it through is a policy the operator believes is in force and
 * is not. The reverse — enforcing against a crawler the published file invites —
 * is how a site quietly disappears from a search index.
 *
 * So the two come from one object:
 *
 * ```ts
 * const policy = botPolicy({ deny: ['training_crawler'], allow: ['perplexitybot'] });
 *
 * app.get('/robots.txt', (_req, res) => res.type('text/plain').send(policy.robotsTxt()));
 * const wd = new WebDecoy({ rules: [policy.rule()] });
 * ```
 *
 * WHAT ROBOTS.TXT IS AND IS NOT
 *
 * It is a request, honoured at the crawler's discretion. The registry records
 * whether each operator *documents* honouring it, which is a claim rather than
 * an observation, and {@link BotPolicy.unenforceable} lists the agents in your
 * deny set that do not even claim it. Those are the ones the rule is actually
 * doing the work for, and `robotsTxt()` names them in a comment so the file
 * itself says which half of the policy is voluntary.
 */

import { BOT_REGISTRY, BOT_CATEGORIES } from '../bots';
import type { BotAgent, BotCategory } from '../bots';
import { BotRule } from './bot-rule';
import type { Rule, BotRuleConfig } from './types';

const AI_CATEGORIES: ReadonlySet<string> = new Set<BotCategory>([
  'training_crawler',
  'ai_search_crawler',
  'ai_agent',
  'ai_assistant',
]);

export interface BotPolicyOptions {
  /**
   * What the policy is against: category names (`'training_crawler'`), agent
   * slugs or display names (`'gptbot'`, `'GPTBot'`), or the literal `'ai'` for
   * every AI client.
   */
  deny?: (BotCategory | 'ai' | string)[];
  /** Never act on these, whatever else matches. Applied last. */
  allow?: string[];
  /** Action the rule takes on a match. @default 'DENY' */
  action?: 'DENY' | 'THROTTLE';
  /** Rule logs but does not block. Does not change what `robotsTxt()` emits. */
  dryRun?: boolean;
}

export interface RobotsTxtOptions {
  /** Absolute sitemap URL, emitted as a `Sitemap:` line. */
  sitemap?: string;
  /** `Crawl-delay` in seconds, applied to the wildcard group. */
  crawlDelay?: number;
  /**
   * Emit a trailing `User-agent: *` group allowing everything else.
   * @default true
   */
  allowOthers?: boolean;
  /** Paths to disallow for every agent, e.g. `['/admin']`. */
  disallow?: string[];
  /**
   * Include the header comment naming agents that do not document honouring
   * robots.txt. @default true
   */
  annotate?: boolean;
}

export class BotPolicy {
  private readonly config: BotRuleConfig;
  /** The agents this policy is against, resolved from the registry. */
  readonly matched: readonly BotAgent[];

  constructor(options: BotPolicyOptions = {}) {
    const deny = options.deny ?? [];
    const allow = new Set((options.allow ?? []).map((a) => a.toLowerCase()));

    const categories = new Set<string>();
    const agents = new Set<string>();
    let ai = false;

    for (const token of deny) {
      if (token === 'ai') ai = true;
      else if ((BOT_CATEGORIES as readonly string[]).includes(token)) categories.add(token);
      else agents.add(token.toLowerCase());
    }

    this.config = {
      categories: [...categories] as BotCategory[],
      agents: [...agents],
      ai,
      allow: options.allow,
      action: options.action,
      dryRun: options.dryRun,
    };

    // Resolved once, so the published file and the rule are reading the same
    // answer rather than each re-deriving it.
    this.matched = BOT_REGISTRY.filter((agent) => {
      if (allow.has(agent.id) || allow.has(agent.name.toLowerCase())) return false;
      return (
        (ai && AI_CATEGORIES.has(agent.category)) ||
        categories.has(agent.category) ||
        agents.has(agent.id) ||
        agents.has(agent.name.toLowerCase())
      );
    });
  }

  /**
   * Agents in the deny set whose operator does not document honouring
   * robots.txt. Publishing still declares the policy; only the rule enforces it
   * against these.
   */
  get unenforceable(): readonly BotAgent[] {
    return this.matched.filter((a) => a.respectsRobots !== true);
  }

  /** The enforcing rule. Denies exactly the agents in {@link matched}. */
  rule(): Rule {
    return new BotRule(this.config);
  }

  /** The published policy, as a `robots.txt` body. */
  robotsTxt(options: RobotsTxtOptions = {}): string {
    const { allowOthers = true, annotate = true } = options;
    const lines: string[] = [];

    if (annotate) {
      lines.push('# Managed by WebDecoy — published and enforced from one policy.');
      const ignoring = this.unenforceable;
      if (ignoring.length > 0) {
        // Named rather than silently included: an operator reading their own
        // robots.txt should be able to see which lines are a request and which
        // are backed by something.
        lines.push(
          '# These do not document honouring robots.txt, so the lines below are a',
          '# request only. The bots() rule is what actually stops them:',
          ...ignoring.map((a) => `#   ${a.name}${a.organization ? ` (${a.organization})` : ''}`),
        );
      }
      lines.push('');
    }

    for (const agent of this.matched) {
      lines.push(`User-agent: ${agent.name}`, 'Disallow: /', '');
    }

    if (allowOthers) {
      lines.push('User-agent: *');
      for (const path of options.disallow ?? []) lines.push(`Disallow: ${path}`);
      // An empty Disallow is the spec's way of saying "nothing is off limits",
      // and it must be present — a group with no rules at all is undefined.
      if ((options.disallow ?? []).length === 0) lines.push('Disallow:');
      if (options.crawlDelay !== undefined) lines.push(`Crawl-delay: ${options.crawlDelay}`);
      lines.push('');
    }

    if (options.sitemap) lines.push(`Sitemap: ${options.sitemap}`, '');

    return lines.join('\n').replace(/\n{3,}/g, '\n\n').trimStart();
  }
}

/**
 * A bot policy you can both publish and enforce. See {@link BotPolicy}.
 */
export function botPolicy(options: BotPolicyOptions = {}): BotPolicy {
  return new BotPolicy(options);
}
