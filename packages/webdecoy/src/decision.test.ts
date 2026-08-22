import { WebDecoy } from './sdk';
import { Decision } from './decision';
import { DecisionCache } from './decision-cache';
import { deriveKey } from './characteristics';
import { rateLimit, tripwire, filter } from './rules';
import type { RequestMetadata } from './types';
import type { RuleContext } from './rules/types';

const req = (over: Partial<RequestMetadata> = {}): RequestMetadata => ({
  method: 'GET',
  path: '/',
  ip: '203.0.113.9',
  user_agent: 'Mozilla/5.0',
  headers: {},
  timestamp: Date.now(),
  ...over,
});

const ctx = (over: Partial<RuleContext> = {}): RuleContext => ({
  ip: '203.0.113.9',
  path: '/',
  method: 'GET',
  headers: {},
  timestamp: Date.now(),
  ...over,
});

describe('the decision the SDK returns', () => {
  it('keeps `allowed` meaning what it meant before', async () => {
    const wd = new WebDecoy({ rules: [] });
    const d = await wd.protect(req());
    expect(d.allowed).toBe(true);
    expect(d.conclusion).toBe('ALLOW');
    expect(d.isAllowed()).toBe(true);
    expect(d.isDenied()).toBe(false);
  });

  it('survives the withEdge copy with its helpers intact', async () => {
    // protect() attaches the edge verdict to whatever decide() produced. When
    // that was a spread of a plain object the methods would have been lost;
    // this is the test that would have caught it.
    const wd = new WebDecoy({ rules: [tripwire()] });
    const d = await wd.protect(req({ path: '/.env' }));
    expect(typeof d.isDenied).toBe('function');
    expect(d.isDenied()).toBe(true);
    expect(d.edge).toBeDefined();
    expect(d.edge?.present).toBe(false);
  });

  it('names the rule that denied, without string-matching', async () => {
    const wd = new WebDecoy({ rules: [tripwire()] });
    const d = await wd.protect(req({ path: '/.env' }));
    expect(d.deniedBy('tripwire')).toBe(true);
    expect(d.deniedBy('rate-limit:1/60s')).toBe(false);
  });

  it('gives every decision a unique id', async () => {
    const wd = new WebDecoy({ rules: [] });
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) ids.add((await wd.protect(req())).id);
    expect(ids.size).toBe(50);
    expect([...ids][0]).toMatch(/^dec_[0-9a-f]{24}$/);
  });

  it('reports the id on the detection too, so the two correlate', async () => {
    const wd = new WebDecoy({ rules: [tripwire()] });
    const d = await wd.protect(req({ path: '/.env' }));
    expect(d.detection.detection_id).toBe(d.id);
  });
});

describe('per-rule results', () => {
  it('records rules that allowed, not only the one that fired', async () => {
    const wd = new WebDecoy({
      rules: [rateLimit({ max: 100, window: 60 }), tripwire()],
    });
    const d = await wd.protect(req({ path: '/.env' }));

    expect(d.results.map((r) => r.rule)).toEqual(['rate-limit:100/60s', 'tripwire']);
    expect(d.results[0]).toMatchObject({ state: 'RUN', conclusion: 'ALLOW' });
    expect(d.results[1]).toMatchObject({ state: 'RUN', conclusion: 'DENY' });
  });

  it('shows a dry-run rule as DENY it did not enforce', async () => {
    const wd = new WebDecoy({ rules: [tripwire({ dryRun: true })] });
    const d = await wd.protect(req({ path: '/.env' }));

    // The whole point of dry run is seeing what it WOULD have done. Reporting
    // the rule's action verbatim would show it as ALLOW.
    expect(d.conclusion).toBe('ALLOW');
    expect(d.allowed).toBe(true);
    expect(d.results[0]).toMatchObject({ state: 'DRY_RUN', conclusion: 'DENY' });
    expect(d.deniedBy('tripwire')).toBe(false);
  });

  it('distinguishes a filter that could not run from one that passed', async () => {
    // No API key means no IP enrichment, so `ip.tor` has nothing to read. This
    // used to report ALLOW, indistinguishable from "checked, and not Tor".
    const wd = new WebDecoy({ rules: [filter({ expression: 'ip.tor' })] });
    const d = await wd.protect(req());
    expect(d.results[0].state).toBe('NOT_RUN');
    expect(d.results[0].reason).toMatch(/API key/);
  });
});

describe('the decision cache', () => {
  const denial = () =>
    new Decision({
      conclusion: 'DENY',
      detection: {
        decision: 'block',
        confidence: 95,
        threat_level: 'HIGH',
        bot_detected: true,
        detection_id: 'dec_test',
        rule_enforced: false,
      },
      results: [{ rule: 'server', state: 'RUN', conclusion: 'DENY' }],
    });

  const allowance = () =>
    new Decision({
      conclusion: 'ALLOW',
      detection: {
        decision: 'allow',
        confidence: 5,
        threat_level: 'MINIMAL',
        bot_detected: false,
        detection_id: 'dec_test',
        rule_enforced: false,
      },
    });

  it('remembers a denial and re-states its rules as CACHED', () => {
    const cache = new DecisionCache();
    expect(cache.set('k', denial())).toBe(true);
    const hit = cache.get('k')?.asCached();
    expect(hit?.conclusion).toBe('DENY');
    expect(hit?.results[0].state).toBe('CACHED');
  });

  it('refuses to cache an allow', () => {
    // Caching an allow is how a client that has since started misbehaving keeps
    // sailing through, and it saves the cheap request rather than the expensive
    // one.
    const cache = new DecisionCache();
    expect(cache.set('k', allowance())).toBe(false);
    expect(cache.get('k')).toBeUndefined();
  });

  it('expires entries', () => {
    const cache = new DecisionCache({ ttl: 1 });
    cache.set('k', denial());
    const now = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(now + 10);
    expect(cache.get('k')).toBeUndefined();
    jest.restoreAllMocks();
  });

  it('is bounded, and evicts oldest first', () => {
    const cache = new DecisionCache({ max: 2 });
    cache.set('a', denial());
    cache.set('b', denial());
    cache.set('c', denial());
    expect(cache.size).toBe(2);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('c')).toBeDefined();
  });

  it('keeps a repeatedly-denied key alive over an untouched one', () => {
    const cache = new DecisionCache({ max: 2 });
    cache.set('a', denial());
    cache.set('b', denial());
    cache.set('a', denial()); // refreshes a's position
    cache.set('c', denial());
    expect(cache.get('a')).toBeDefined();
    expect(cache.get('b')).toBeUndefined();
  });

  it('a zero ttl means never', () => {
    const cache = new DecisionCache({ ttl: 0 });
    expect(cache.set('k', denial())).toBe(false);
  });
});

describe('characteristics', () => {
  it('defaults to the IP', () => {
    expect(deriveKey(ctx())).toBe('203.0.113.9');
  });

  it('composes several into one key', () => {
    expect(deriveKey(ctx({ path: '/api' }), ['ip', 'path'])).toBe('203.0.113.9|/api');
  });

  it('takes a custom accessor', () => {
    const key = deriveKey(ctx({ headers: { 'x-api-key': 'tenant-7' } }), [
      (c) => c.headers['x-api-key'],
    ]);
    expect(key).toBe('tenant-7');
  });

  it('falls back to the IP when a characteristic is absent', () => {
    // Not '' and not 'undefined' — either would bucket every unauthenticated
    // request together, so one tenant's limit would take out anonymous traffic.
    expect(deriveKey(ctx(), [(c) => c.headers['x-api-key']])).toBe('203.0.113.9');
  });

  it('falls back to the IP when a characteristic throws', () => {
    expect(
      deriveKey(ctx(), [
        () => {
          throw new Error('bad accessor');
        },
      ]),
    ).toBe('203.0.113.9');
  });

  it('rate-limits on the characteristic rather than the IP', async () => {
    const wd = new WebDecoy({
      characteristics: [(c) => c.headers['x-api-key']],
      rules: [rateLimit({ max: 1, window: 60, action: 'DENY' })],
    });

    // Two callers behind one NAT: separate buckets, because the key is the API
    // key rather than the address they share.
    const a1 = await wd.protect(req({ headers: { 'x-api-key': 'a' } }));
    const b1 = await wd.protect(req({ headers: { 'x-api-key': 'b' } }));
    const a2 = await wd.protect(req({ headers: { 'x-api-key': 'a' } }));

    expect(a1.allowed).toBe(true);
    expect(b1.allowed).toBe(true);
    expect(a2.allowed).toBe(false);
  });

  it("lets a rule's own keyBy win over the SDK characteristics", async () => {
    const wd = new WebDecoy({
      characteristics: [(c) => c.headers['x-api-key']],
      rules: [rateLimit({ max: 1, window: 60, action: 'DENY', keyBy: (c) => c.ip })],
    });

    const first = await wd.protect(req({ headers: { 'x-api-key': 'a' } }));
    const second = await wd.protect(req({ headers: { 'x-api-key': 'b' } }));

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false); // same IP, and keyBy said IP
  });
});
