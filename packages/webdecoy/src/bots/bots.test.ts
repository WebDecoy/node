import {
  matchUserAgent,
  classifyUserAgent,
  clearBotCache,
  BOT_REGISTRY,
  BOT_CATEGORIES,
} from './index';

beforeEach(() => clearBotCache());

describe('matchUserAgent', () => {
  it('identifies AI training crawlers from a real User-Agent', () => {
    const gpt = matchUserAgent('Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)');
    expect(gpt?.id).toBe('gptbot');
    expect(gpt?.category).toBe('training_crawler');
    expect(gpt?.organization).toBe('OpenAI');

    const claude = matchUserAgent('Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)');
    expect(claude?.id).toBe('claudebot');
    expect(claude?.category).toBe('training_crawler');
  });

  it('is case-insensitive, because User-Agent casing is not a contract', () => {
    expect(matchUserAgent('GPTBOT/1.1')?.id).toBe('gptbot');
    expect(matchUserAgent('gptbot/1.1')?.id).toBe('gptbot');
  });

  it('returns undefined for an ordinary browser', () => {
    expect(
      matchUserAgent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
      ),
    ).toBeUndefined();
  });

  it('returns undefined for empty and missing input rather than throwing', () => {
    expect(matchUserAgent(undefined)).toBeUndefined();
    expect(matchUserAgent(null)).toBeUndefined();
    expect(matchUserAgent('')).toBeUndefined();
  });

  it('caches both hits and misses', () => {
    // A miss caches `null`, which must not be confused with "not cached" —
    // otherwise every browser request rescans all 168 agents forever.
    const ua = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0';
    expect(matchUserAgent(ua)).toBeUndefined();
    expect(matchUserAgent(ua)).toBeUndefined();
    expect(matchUserAgent('GPTBot/1.1')?.id).toBe('gptbot');
    expect(matchUserAgent('GPTBot/1.1')?.id).toBe('gptbot');
  });

  it('bounds the cache against attacker-supplied User-Agents', () => {
    // The key is client-controlled. Unbounded growth here would be a memory
    // exhaustion vector, so the map must not keep growing past its cap.
    for (let i = 0; i < 2500; i++) matchUserAgent(`UniqueAgent/${i}`);
    // Still correct after whatever eviction happened.
    expect(matchUserAgent('GPTBot/1.1')?.id).toBe('gptbot');
  });
});

describe('registry integrity', () => {
  it('carries the full generated table', () => {
    expect(BOT_REGISTRY.length).toBe(169);
    expect(BOT_CATEGORIES).toContain('training_crawler');
    expect(BOT_CATEGORIES).toContain('search_crawler');
  });

  it('has only lowercase patterns, which the matcher relies on', () => {
    // The matcher lowercases the UA and compares verbatim, mirroring Go's
    // strings.Contains(uaLower, pattern). An uppercase pattern would be dead.
    const offenders = BOT_REGISTRY.flatMap((a) =>
      a.uaPatterns.filter((p) => p !== p.toLowerCase()).map((p) => `${a.id}:${p}`),
    );
    expect(offenders).toEqual([]);
  });

  it('has no empty pattern, which would match every request', () => {
    const offenders = BOT_REGISTRY.filter((a) => a.uaPatterns.some((p) => p === ''));
    expect(offenders).toEqual([]);
  });

  it('puts AI data scrapers before other categories, as Go does', () => {
    // Match precedence is positional. If the generator ever sorts the table,
    // this is what notices.
    const firstTraining = BOT_REGISTRY.findIndex((a) => a.category === 'training_crawler');
    const firstGeneric = BOT_REGISTRY.findIndex((a) => a.category === 'generic_scraper');
    expect(firstTraining).toBe(0);
    expect(firstGeneric).toBeGreaterThan(firstTraining);
  });
});

describe('classifyUserAgent', () => {
  it('describes a known agent completely', () => {
    const v = classifyUserAgent('Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)');
    expect(v).toMatchObject({
      known: true,
      id: 'gptbot',
      name: 'GPTBot',
      category: 'training_crawler',
      organization: 'OpenAI',
      isAI: true,
    });
    expect(v.score).toBeGreaterThan(0);
  });

  it('reports an unknown agent as known:false / category:none, never undefined', () => {
    const v = classifyUserAgent('Mozilla/5.0 Chrome/137.0.0.0');
    expect(v.known).toBe(false);
    expect(v.category).toBe('none');
    expect(v.score).toBe(0);
    expect(v.isAI).toBe(false);
  });

  it('flags every AI category as AI and ordinary crawlers as not', () => {
    expect(classifyUserAgent('GPTBot/1.1').isAI).toBe(true);
    expect(classifyUserAgent('PerplexityBot/1.0').isAI).toBe(true);
    // Googlebot is a search engine, not an AI client. Getting this wrong means a
    // customer's `ai: true` rule deindexes their site.
    const google = classifyUserAgent(
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    );
    expect(google.known).toBe(true);
    expect(google.category).toBe('search_crawler');
    expect(google.isAI).toBe(false);
  });
});
