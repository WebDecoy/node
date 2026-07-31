import { readEdgeVerdict, EDGE_CLASS_HEADER, EDGE_CLEARANCE_HEADER } from './edge';
import { filter } from './rules';
import { WebDecoy } from './sdk';
import type { RuleContext } from './rules/types';

/**
 * Reading the edge validator's tag.
 *
 * The worker has set `x-wd-clearance` on every forwarded request since the
 * validator shipped, and nothing read it — so on a scoped route an application's
 * only options were the edge's pass or the edge's 403, and a 403 on public content
 * hits every client that cannot run JavaScript.
 *
 * The tests that matter most here are the ones about ABSENCE. An application will
 * use this to decide whether to serve someone less, so "we don't know" must never
 * read as "browser", and a value the client supplied must never read as ours.
 */

describe('readEdgeVerdict', () => {
  it('parses both headers into typed values', () => {
    const edge = readEdgeVerdict({
      [EDGE_CLEARANCE_HEADER]: 'valid',
      [EDGE_CLASS_HEADER]: 'script',
    });
    expect(edge.present).toBe(true);
    expect(edge.clearance).toBe('valid');
    expect(edge.class).toBe('script');
    expect(edge.isScript).toBe(true);
    expect(edge.isBrowser).toBe(false);
  });

  it('reports absence as absence, not as browser', () => {
    // The whole point. A request the edge never touched carries no information,
    // and an application that reads `isBrowser` off it would be skipping checks
    // for exactly the traffic that bypassed the edge.
    const edge = readEdgeVerdict({ 'user-agent': 'curl/8.7.1' });
    expect(edge.present).toBe(false);
    expect(edge.class).toBeUndefined();
    expect(edge.isBrowser).toBe(false);
    expect(edge.isScript).toBe(false);
    expect(edge.isUnattestedNonBrowser).toBe(false);
  });

  it('handles no headers at all', () => {
    expect(readEdgeVerdict(undefined).present).toBe(false);
    expect(readEdgeVerdict({}).present).toBe(false);
  });

  it('tolerates mixed-case header names, since adapters differ', () => {
    const edge = readEdgeVerdict({ 'X-WD-Class': 'crawler' });
    expect(edge.class).toBe('crawler');
    expect(edge.isCrawler).toBe(true);
  });

  it('drops an unrecognised class rather than passing it through', () => {
    // A value outside the closed set means version skew or something that is not
    // our worker. Silence beats handing a caller a string they might branch on.
    const edge = readEdgeVerdict({ [EDGE_CLASS_HEADER]: 'definitely-a-human' });
    expect(edge.class).toBeUndefined();
    expect(edge.present).toBe(false);
  });

  it('keeps an unknown clearance label — the validator gains those faster than we ship', () => {
    const edge = readEdgeVerdict({ [EDGE_CLEARANCE_HEADER]: 'some-future-label' });
    expect(edge.present).toBe(true);
    expect(edge.clearance).toBe('some-future-label');
    expect(edge.class).toBeUndefined();
  });

  it('isUnattestedNonBrowser excludes verified', () => {
    // The predicate most callers want is "cheapen this", and the one population
    // you must never cheapen for is the one whose identity was actually attested.
    expect(readEdgeVerdict({ [EDGE_CLASS_HEADER]: 'script' }).isUnattestedNonBrowser).toBe(true);
    expect(readEdgeVerdict({ [EDGE_CLASS_HEADER]: 'crawler' }).isUnattestedNonBrowser).toBe(true);
    expect(readEdgeVerdict({ [EDGE_CLASS_HEADER]: 'verified' }).isUnattestedNonBrowser).toBe(false);
    expect(readEdgeVerdict({ [EDGE_CLASS_HEADER]: 'browser' }).isUnattestedNonBrowser).toBe(false);
  });
});

/**
 * Filter expressions could always match this with req.header("x-wd-class"). A
 * named field exists so it is discoverable, spelled once rather than in every
 * customer's expression, and survives us renaming a header.
 */
describe('edge.* in filter expressions', () => {
  function ctx(headers: Record<string, string>): RuleContext {
    return {
      ip: '203.0.113.5',
      path: '/search',
      method: 'GET',
      headers,
      timestamp: 1_700_000_000_000,
      edge: readEdgeVerdict(headers),
    };
  }

  it('matches on edge.class', () => {
    const rule = filter({ expression: 'edge.class == "script"', action: 'THROTTLE' });
    expect(rule.evaluate(ctx({ [EDGE_CLASS_HEADER]: 'script' })).action).toBe('THROTTLE');
    expect(rule.evaluate(ctx({ [EDGE_CLASS_HEADER]: 'browser' })).action).toBe('ALLOW');
  });

  it('does not fire when the edge never classified', () => {
    // An undefined class must make the comparison false. If it coerced to a
    // match, every request that bypassed the edge would be throttled.
    const rule = filter({ expression: 'edge.class == "script"', action: 'THROTTLE' });
    expect(rule.evaluate(ctx({})).action).toBe('ALLOW');
  });

  it('matches on the boolean shorthands', () => {
    const rule = filter({ expression: 'edge.script', action: 'THROTTLE' });
    expect(rule.evaluate(ctx({ [EDGE_CLASS_HEADER]: 'script' })).action).toBe('THROTTLE');
    expect(rule.evaluate(ctx({ [EDGE_CLASS_HEADER]: 'verified' })).action).toBe('ALLOW');
  });

  it('can require that the edge was actually in front of the request', () => {
    const rule = filter({
      expression: 'edge.present and edge.class == "crawler"',
      action: 'THROTTLE',
    });
    expect(rule.evaluate(ctx({ [EDGE_CLASS_HEADER]: 'crawler' })).action).toBe('THROTTLE');
    expect(rule.evaluate(ctx({})).action).toBe('ALLOW');
  });

  it('matches on the clearance verdict', () => {
    const rule = filter({ expression: 'edge.clearance == "missing"', action: 'DENY' });
    expect(rule.evaluate(ctx({ [EDGE_CLEARANCE_HEADER]: 'missing' })).action).toBe('DENY');
    expect(rule.evaluate(ctx({ [EDGE_CLEARANCE_HEADER]: 'valid' })).action).toBe('ALLOW');
  });

  it('the raw-header form still works, so nobody has to migrate', () => {
    const rule = filter({
      expression: 'req.header("x-wd-class") == "script"',
      action: 'THROTTLE',
    });
    expect(rule.evaluate(ctx({ [EDGE_CLASS_HEADER]: 'script' })).action).toBe('THROTTLE');
  });
});

/**
 * Server-side detection needs a signal it can actually use (0.7.0).
 *
 * The unified score weights honeypot hits at 38% and user-agent at 1% —
 * deliberately, because a user agent is trivially spoofed. A middleware with no
 * rules can only contribute the 1% signals, so it scores ~0 whatever it sees.
 * A page view by an unknown client scores near zero, while the same client
 * walking into a trap scores an order of magnitude higher.
 *
 * Raising the user-agent weight would be backwards — it would score the clients
 * honest enough to identify themselves and miss every attacker who does not. So
 * an install with no rules gets tripwires instead of nothing.
 */
describe('default rules', () => {
  it('an SDK with no rules configured still has tripwires', () => {
    const sdk = new WebDecoy({ apiKey: 'sk_live_test' });
    const result = sdk.evaluateRules({
      method: 'GET',
      path: '/.env',
      ip: '203.0.113.9',
      headers: {},
      timestamp: Date.now(),
    });
    expect(result).not.toBeNull();
    expect(result!.violations.length).toBeGreaterThan(0);
  });

  it('ordinary paths are untouched, so a visitor cannot trip one', () => {
    const sdk = new WebDecoy({ apiKey: 'sk_live_test' });
    for (const path of ['/', '/checkout', '/api/orders', '/about']) {
      const result = sdk.evaluateRules({
        method: 'GET', path, ip: '203.0.113.9', headers: {}, timestamp: Date.now(),
      });
      expect(result?.violations ?? []).toHaveLength(0);
    }
  });

  it('rules: [] opts out explicitly', () => {
    const sdk = new WebDecoy({ apiKey: 'sk_live_test', rules: [] });
    const result = sdk.evaluateRules({
      method: 'GET', path: '/.env', ip: '203.0.113.9', headers: {}, timestamp: Date.now(),
    });
    expect(result).toBeNull();
  });
})
