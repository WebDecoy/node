import {
  createTestHarness,
  request,
  get,
  post,
  botRequest,
  expectDenied,
  expectAllowed,
  expectRuleState,
  protectMany,
} from './testing';
import { tripwire, rateLimit, filter, bots, attackSignatures } from './rules';
import { consoleLogger, silentLogger, fromPino } from './logger';

describe('the request builders', () => {
  it('fills in the boilerplate', () => {
    const r = request();
    expect(r.method).toBe('GET');
    expect(r.ip).toBeTruthy();
    expect(r.user_agent).toMatch(/Chrome/);
  });

  it('splits a query off the path, which is where signatures look', () => {
    const r = get('/search?q=hello&page=2');
    expect(r.path).toBe('/search');
    expect(r.query).toBe('q=hello&page=2');
  });

  it('leaves query undefined when there is none', () => {
    expect(get('/plain').query).toBeUndefined();
  });

  it('builds a POST with a body', () => {
    const r = post('/submit', '{"a":1}');
    expect(r).toMatchObject({ method: 'POST', path: '/submit', body: '{"a":1}' });
  });

  it('builds a bot request', () => {
    expect(botRequest('GPTBot/1.0').user_agent).toBe('GPTBot/1.0');
  });
});

describe('the harness', () => {
  it('does not reach the network even with a key in the environment', async () => {
    // A WEBDECOY_API_KEY in CI would otherwise turn every unit test into a live
    // call, and file test traffic as real detections in the dashboard.
    const fetchSpy = jest.fn();
    const original = globalThis.fetch;
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    try {
      const wd = createTestHarness({ apiKey: 'sk_live_should_be_ignored', rules: [tripwire()] });
      await wd.protect(get('/'));
      await wd.protect(get('/.env'));
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = original;
    }
  });

  it('opts into the network explicitly', () => {
    const wd = createTestHarness({ apiKey: 'sk_test_abc', allowNetwork: true });
    expect(wd.getClient()).not.toBeNull();
  });

  it('gives each harness its own rule state', async () => {
    // A shared module-level SDK leaks rate-limit counters between cases, and the
    // second test to run fails for reasons belonging to the first.
    const config = { rules: [rateLimit({ max: 1, window: 60, action: 'DENY' as const })] };
    const a = createTestHarness(config);
    const b = createTestHarness({ rules: [rateLimit({ max: 1, window: 60, action: 'DENY' })] });

    expectAllowed(await a.protect(get('/')));
    expectDenied(await a.protect(get('/')));
    expectAllowed(await b.protect(get('/')));
  });

  it('is silent', async () => {
    const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const wd = createTestHarness({ debug: true, rules: [tripwire()] });
      await wd.protect(get('/.env'));
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});

describe('the assertions', () => {
  const wd = createTestHarness({ rules: [tripwire(), attackSignatures()] });

  it('passes on the outcomes they name', async () => {
    expectDenied(await wd.protect(get('/.env')));
    expectDenied(await wd.protect(get('/.env')), { rule: 'tripwire' });
    expectAllowed(await wd.protect(get('/')));
  });

  it('matches a reason by substring or pattern', async () => {
    const d = await wd.protect(get('/?x=${jndi:ldap://e/a}'));
    expectDenied(d, { reason: 'JNDI' });
    expectDenied(d, { reason: /jndi/i });
  });

  it('fails with the rules and their states, not just true/false', async () => {
    // "expected false to be true" tells you nothing about which of six rules was
    // supposed to fire.
    let message = '';
    try {
      expectDenied(await wd.protect(get('/')));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('conclusion=ALLOW');
    expect(message).toContain('tripwire=ALLOW');
    expect(message).toContain('attack-signatures=ALLOW');
  });

  it('says which rule was expected to deny when another one did', async () => {
    let message = '';
    try {
      expectDenied(await wd.protect(get('/.env')), { rule: 'attack-signatures' });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/Expected attack-signatures to deny/);
  });

  it('fails expectAllowed on ERROR, which is not the same as allowed', async () => {
    const broken = createTestHarness({ rules: [tripwire()] });
    // No IP is a malformed request, which the SDK fails open on — allowed to
    // serve, but no verdict was reached, and a test should not accept that as a
    // pass.
    const d = await broken.protect(request({ ip: '' }));
    expect(d.conclusion).toBe('ERROR');
    expect(d.allowed).toBe(true);
    expect(() => expectAllowed(d)).toThrow(/conclusion=ERROR/);
  });

  it('asserts a rule state', async () => {
    const dry = createTestHarness({ rules: [tripwire({ dryRun: true })] });
    const d = await dry.protect(get('/.env'));
    expectAllowed(d);
    expectRuleState(d, 'tripwire', 'DRY_RUN');
    expect(() => expectRuleState(d, 'tripwire', 'RUN')).toThrow(/got DRY_RUN/);
    expect(() => expectRuleState(d, 'nope', 'RUN')).toThrow(/No rule named nope/);
  });

  it('sees NOT_RUN for a filter with no enrichment', async () => {
    const wd2 = createTestHarness({ rules: [filter({ expression: 'ip.tor' })] });
    expectRuleState(await wd2.protect(get('/')), 'filter:ip.tor', 'NOT_RUN');
  });
});

describe('protectMany', () => {
  it('runs a rate limit to its edge without sleeping', async () => {
    const wd = createTestHarness({ rules: [rateLimit({ max: 3, window: 60, action: 'DENY' })] });
    const results = await protectMany(wd, get('/'), 5);
    expect(results.map((r) => r.conclusion)).toEqual([
      'ALLOW',
      'ALLOW',
      'ALLOW',
      'DENY',
      'DENY',
    ]);
  });

  it('takes a factory for per-request variation', async () => {
    const wd = createTestHarness({
      characteristics: [(c) => c.headers['x-api-key']],
      rules: [rateLimit({ max: 1, window: 60, action: 'DENY' })],
    });
    let n = 0;
    const results = await protectMany(wd, () => request({ headers: { 'x-api-key': `k${n++}` } }), 3);
    expect(results.every((r) => r.conclusion === 'ALLOW')).toBe(true);
  });
});

describe('the logger', () => {
  it('gates debug and info, but never warnings or errors', () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const quiet = consoleLogger(false);
      quiet.debug('d');
      quiet.info('i');
      quiet.warn('w');
      expect(log).not.toHaveBeenCalled();
      // A violation that failed to report is not debug output.
      expect(warn).toHaveBeenCalledWith('[WebDecoy] w');
    } finally {
      log.mockRestore();
      warn.mockRestore();
    }
  });

  it('passes structured fields through', () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      consoleLogger(true).debug('hello', { a: 1 });
      expect(log).toHaveBeenCalledWith('[WebDecoy] hello', { a: 1 });
    } finally {
      log.mockRestore();
    }
  });

  it('routes through a provided logger instead of console', async () => {
    const lines: string[] = [];
    const custom = {
      debug: (m: string) => lines.push(`debug:${m}`),
      info: (m: string) => lines.push(`info:${m}`),
      warn: (m: string) => lines.push(`warn:${m}`),
      error: (m: string) => lines.push(`error:${m}`),
    };
    const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const { WebDecoy } = await import('./sdk');
      new WebDecoy({ logger: custom, debug: true, rules: [tripwire()] });
      expect(lines.some((l) => l.startsWith('debug:Initialized'))).toBe(true);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('flips the argument order for a pino-style logger', () => {
    const calls: unknown[][] = [];
    const pino = {
      debug: (...a: unknown[]) => calls.push(a),
      info: (...a: unknown[]) => calls.push(a),
      warn: (...a: unknown[]) => calls.push(a),
      error: (...a: unknown[]) => calls.push(a),
    };
    // Passing pino directly would type-check and then quietly drop every field.
    fromPino(pino as never).info('hello', { a: 1 });
    expect(calls[0]).toEqual([{ a: 1 }, 'hello']);
  });

  it('silentLogger discards everything', () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      silentLogger.debug('x');
      silentLogger.error('y');
      expect(log).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
    }
  });
});

describe('the harness under real rules', () => {
  it('reads naturally end to end', async () => {
    const wd = createTestHarness({
      rules: [bots({ categories: ['training_crawler'] }), tripwire(), attackSignatures()],
    });

    expectDenied(await wd.protect(botRequest('GPTBot/1.0')), { rule: 'bots' });
    expectDenied(await wd.protect(get('/.git/config')), { rule: 'tripwire' });
    expectDenied(await wd.protect(get("/search?q=1' UNION SELECT p FROM u")), {
      rule: 'attack-signatures',
    });
    expectAllowed(await wd.protect(get('/search?q=coffee%20or%20tea')));
    expectAllowed(await wd.protect(botRequest('Googlebot/2.1')));
  });
});
