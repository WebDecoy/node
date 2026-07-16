import { RuleEngine } from './rule-engine';
import type { Rule, RuleContext, RuleResult } from './types';

/** A stub rule that always returns a fixed result. */
function fixedRule(result: RuleResult): Rule {
  return { name: result.rule, evaluate: (): RuleResult => result };
}

function ctx(cookie?: string): RuleContext {
  return {
    ip: '203.0.113.5',
    path: '/wp-admin.php',
    method: 'GET',
    headers: cookie ? { cookie } : {},
    timestamp: 1_700_000_000_000,
  };
}

describe('RuleEngine clearance forwarding (#136)', () => {
  it('attaches the wd_clearance token to a tripwire violation', () => {
    const engine = new RuleEngine([
      fixedRule({ action: 'DENY', rule: 'tripwire', reason: 'honeypot path' }),
    ]);
    const res = engine.evaluate(ctx('foo=1; wd_clearance=TOK123; bar=2'));
    expect(res.violations[0].rule).toBe('tripwire');
    expect(res.violations[0].clearance).toBe('TOK123');
  });

  it('does NOT attach clearance to non-tripwire rules (heuristics never deny fp)', () => {
    const engine = new RuleEngine([
      fixedRule({ action: 'DENY', rule: 'filter', reason: 'ip.tor' }),
    ]);
    const res = engine.evaluate(ctx('wd_clearance=TOK123'));
    expect(res.violations[0].rule).toBe('filter');
    expect(res.violations[0].clearance).toBeUndefined();
  });

  it('leaves clearance undefined for a tripwire when there is no cookie', () => {
    const engine = new RuleEngine([
      fixedRule({ action: 'DENY', rule: 'tripwire', reason: 'honeypot path' }),
    ]);
    const res = engine.evaluate(ctx());
    expect(res.violations[0].clearance).toBeUndefined();
  });

  it('leaves clearance undefined when the cookie has no wd_clearance', () => {
    const engine = new RuleEngine([
      fixedRule({ action: 'DENY', rule: 'tripwire', reason: 'honeypot path' }),
    ]);
    const res = engine.evaluate(ctx('session=abc; theme=dark'));
    expect(res.violations[0].clearance).toBeUndefined();
  });
});
