import { BotRule } from './bot-rule';
import { FilterRule } from './filter-rule';
import { classifyUserAgent } from '../bots';
import type { RuleContext } from './types';

function ctx(userAgent: string): RuleContext {
  return {
    ip: '203.0.113.9',
    path: '/',
    method: 'GET',
    userAgent,
    headers: {},
    timestamp: Date.now(),
    bot: classifyUserAgent(userAgent),
  };
}

const GPTBOT = 'Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)';
const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const PERPLEXITY = 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)';
const CHROME =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';

describe('BotRule', () => {
  it('denies the category it was given', () => {
    const rule = new BotRule({ categories: ['training_crawler'] });
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
  });

  it('leaves search crawlers alone when only training crawlers are blocked', () => {
    // The whole reason the two categories are distinct. A rule that blocks
    // GPTBot must not take Googlebot with it.
    const rule = new BotRule({ categories: ['training_crawler'] });
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('ALLOW');
  });

  it('never acts on an unrecognised User-Agent', () => {
    const rule = new BotRule({ categories: ['training_crawler'], ai: true });
    expect(rule.evaluate(ctx(CHROME)).action).toBe('ALLOW');
  });

  it('acts on the whole AI family with ai:true', () => {
    const rule = new BotRule({ ai: true });
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
    expect(rule.evaluate(ctx(PERPLEXITY)).action).toBe('DENY');
    // ...but not on a plain search engine.
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('ALLOW');
  });

  it('lets allow[] override a broader match', () => {
    const rule = new BotRule({ ai: true, allow: ['perplexitybot'] });
    expect(rule.evaluate(ctx(PERPLEXITY)).action).toBe('ALLOW');
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
  });

  it('accepts display names as well as slugs, in either case', () => {
    // 'GPTBot' is what the dashboard shows; 'gptbot' is what the registry calls
    // it. Requiring the right one is a support ticket per install.
    expect(new BotRule({ agents: ['GPTBot'] }).evaluate(ctx(GPTBOT)).action).toBe('DENY');
    expect(new BotRule({ agents: ['gptbot'] }).evaluate(ctx(GPTBOT)).action).toBe('DENY');
    expect(new BotRule({ ai: true, allow: ['GPTBot'] }).evaluate(ctx(GPTBOT)).action).toBe('ALLOW');
  });

  it('honours THROTTLE and dryRun', () => {
    expect(new BotRule({ ai: true, action: 'THROTTLE' }).evaluate(ctx(GPTBOT)).action).toBe(
      'THROTTLE',
    );
    const dry = new BotRule({ ai: true, dryRun: true }).evaluate(ctx(GPTBOT));
    expect(dry.action).toBe('ALLOW');
    expect(dry.metadata?.dryRun).toBe(true);
  });

  it('does not claim tripwire-grade confidence', () => {
    // A User-Agent match repeats a claim; a tripwire hit proves behaviour.
    // Reporting 100 here would let a downstream consumer treat them alike.
    const result = new BotRule({ ai: true }).evaluate(ctx(GPTBOT));
    expect(result.metadata?.confidence).toBeLessThan(100);
  });

  it('allows everything when configured with nothing', () => {
    // An empty config must be inert, not a default-deny that takes a site down.
    const rule = new BotRule();
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('ALLOW');
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('ALLOW');
  });
});

describe('bot fields in filter expressions', () => {
  it('matches on category using the dashboard vocabulary', () => {
    const rule = new FilterRule({ expression: 'bot.category == "training_crawler"' });
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('ALLOW');
  });

  it('matches on bot.ai', () => {
    const rule = new FilterRule({ expression: 'bot.ai' });
    expect(rule.evaluate(ctx(PERPLEXITY)).action).toBe('DENY');
    expect(rule.evaluate(ctx(CHROME)).action).toBe('ALLOW');
  });

  it('composes with other namespaces', () => {
    const rule = new FilterRule({
      expression: 'bot.ai and bot.organization == "OpenAI"',
    });
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
    expect(rule.evaluate(ctx(PERPLEXITY)).action).toBe('ALLOW');
  });

  it('supports in[] over categories', () => {
    const rule = new FilterRule({
      expression: 'bot.category in ["training_crawler", "generic_scraper"]',
    });
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('ALLOW');
  });

  it('compares name against undefined rather than "" for an unknown agent', () => {
    // If unknown agents reported an empty name, `bot.name != "GPTBot"` would be
    // true for every browser — turning a narrow rule into a site-wide block.
    const rule = new FilterRule({ expression: 'bot.name != "GPTBot"' });
    expect(rule.evaluate(ctx(CHROME)).action).toBe('ALLOW');
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('DENY');
  });

  it('reports bot.known as false, not undefined, for a browser', () => {
    const known = new FilterRule({ expression: 'bot.known' });
    expect(known.evaluate(ctx(CHROME)).action).toBe('ALLOW');
    expect(known.evaluate(ctx(GPTBOT)).action).toBe('DENY');

    const unknown = new FilterRule({ expression: 'not bot.known' });
    expect(unknown.evaluate(ctx(CHROME)).action).toBe('DENY');
    expect(unknown.evaluate(ctx(GPTBOT)).action).toBe('ALLOW');
  });

  it('compares bot.score numerically', () => {
    const rule = new FilterRule({ expression: 'bot.score >= 80' });
    expect(rule.evaluate(ctx(GPTBOT)).action).toBe('DENY');
    // Googlebot's registry score is well below the AI crawlers'.
    expect(rule.evaluate(ctx(GOOGLEBOT)).action).toBe('ALLOW');
  });
});
