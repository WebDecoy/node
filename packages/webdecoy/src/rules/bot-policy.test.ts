import { botPolicy } from './bot-policy';
import { BOT_REGISTRY } from '../bots';
import type { RuleContext } from './types';
import { classifyUserAgent } from '../bots';

const ctxFor = (ua: string): RuleContext => ({
  ip: '203.0.113.9',
  path: '/',
  method: 'GET',
  userAgent: ua,
  headers: {},
  timestamp: Date.now(),
  bot: classifyUserAgent(ua),
});

/** The User-agent tokens a robots.txt body disallows. */
function disallowed(body: string): string[] {
  const out: string[] = [];
  const lines = body.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const ua = /^User-agent:\s*(.+)$/.exec(lines[i]);
    if (!ua || ua[1] === '*') continue;
    if (/^Disallow:\s*\/\s*$/.test(lines[i + 1] ?? '')) out.push(ua[1]);
  }
  return out;
}

describe('botPolicy', () => {
  it('publishes and enforces the same set — this is the whole point', () => {
    const policy = botPolicy({ deny: ['training_crawler'], allow: ['perplexitybot'] });
    const rule = policy.rule();

    const published = new Set(disallowed(policy.robotsTxt()));
    expect(published.size).toBeGreaterThan(10);

    // Every agent the file disallows is one the rule denies, and vice versa.
    // Drift between the two is a policy the operator believes is in force and
    // is not.
    for (const agent of BOT_REGISTRY) {
      const ua = `${agent.uaPatterns[0]}/1.0`;
      const verdict = classifyUserAgent(ua);
      // Only assert on agents this UA actually resolves to — several share
      // substrings and the matcher takes the first hit.
      if (verdict.id !== agent.id) continue;

      const denied = rule.evaluate(ctxFor(ua)).action === 'DENY';
      expect({ agent: agent.id, denied }).toEqual({
        agent: agent.id,
        denied: published.has(agent.name),
      });
    }
  });

  it('honours an allow-list in both outputs at once', () => {
    const policy = botPolicy({ deny: ['training_crawler'], allow: ['perplexitybot'] });
    expect(disallowed(policy.robotsTxt())).not.toContain('PerplexityBot');
    expect(policy.rule().evaluate(ctxFor('PerplexityBot/1.0')).action).toBe('ALLOW');
  });

  it('takes categories, agent names and the ai shorthand together', () => {
    const byCategory = botPolicy({ deny: ['training_crawler'] });
    const byName = botPolicy({ deny: ['GPTBot'] });
    const byAi = botPolicy({ deny: ['ai'] });

    expect(byCategory.matched.some((a) => a.id === 'gptbot')).toBe(true);
    expect(byName.matched.map((a) => a.id)).toEqual(['gptbot']);
    // 'ai' spans four categories, so it must be a superset of any one of them.
    expect(byAi.matched.length).toBeGreaterThan(byCategory.matched.length);
  });

  it('names the agents that do not document honouring robots.txt', () => {
    const policy = botPolicy({ deny: ['training_crawler'] });
    const ignoring = policy.unenforceable;
    expect(ignoring.length).toBeGreaterThan(0);

    const body = policy.robotsTxt();
    // The file should say which of its own lines are only a request.
    for (const agent of ignoring) {
      expect(body).toContain(`#   ${agent.name}`);
    }
    expect(body).toMatch(/request only/);
  });

  it('can be published without the annotation', () => {
    const body = botPolicy({ deny: ['training_crawler'] }).robotsTxt({ annotate: false });
    expect(body.startsWith('User-agent:')).toBe(true);
    expect(body).not.toContain('#');
  });

  it('emits a wildcard group that allows everything else', () => {
    const body = botPolicy({ deny: ['GPTBot'] }).robotsTxt();
    // An empty Disallow is the spec's "nothing is off limits". A group with no
    // rules at all is undefined behaviour.
    expect(body).toMatch(/User-agent: \*\nDisallow:\s*\n/);
  });

  it('carries sitemap, crawl delay and shared disallows', () => {
    const body = botPolicy({ deny: [] }).robotsTxt({
      sitemap: 'https://example.com/sitemap.xml',
      crawlDelay: 10,
      disallow: ['/admin', '/internal'],
    });
    expect(body).toContain('Sitemap: https://example.com/sitemap.xml');
    expect(body).toContain('Crawl-delay: 10');
    expect(body).toContain('Disallow: /admin');
    expect(body).toContain('Disallow: /internal');
  });

  it('is a valid empty policy when nothing is denied', () => {
    const policy = botPolicy();
    expect(policy.matched).toHaveLength(0);
    expect(disallowed(policy.robotsTxt())).toEqual([]);
    expect(policy.rule().evaluate(ctxFor('GPTBot/1.0')).action).toBe('ALLOW');
  });

  it('never emits three blank lines in a row', () => {
    const body = botPolicy({ deny: ['ai'] }).robotsTxt({ sitemap: 'https://e.com/s.xml' });
    expect(body).not.toMatch(/\n\n\n/);
  });
});
