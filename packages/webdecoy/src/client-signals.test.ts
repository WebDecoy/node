import {
  clientSignals,
  MemoryClientSignalStore,
  readClientSession,
  CLIENT_SESSION_COOKIE,
  type ClientSignalStore,
  type ClientVerdict,
} from './client-signals';
import { createCaptchaEndpoints } from './captcha';
import { createTestHarness, request, expectDenied, expectAllowed, expectRuleState } from './testing';
import type { RuleContext } from './rules/types';

const verdict = (over: Partial<ClientVerdict> = {}): ClientVerdict => ({
  sessionId: 's1',
  score: 0.9,
  recommendation: 'block',
  at: Date.now(),
  ...over,
});

const ctx = (headers: Record<string, string> = {}): RuleContext => ({
  ip: '203.0.113.9',
  path: '/',
  method: 'GET',
  headers,
  timestamp: Date.now(),
});

const withSession = (id: string) => ({ cookie: `a=1; ${CLIENT_SESSION_COOKIE}=${id}; b=2` });

describe('reading the browser session', () => {
  it('finds the cookie among others', () => {
    expect(readClientSession(withSession('abc'))).toBe('abc');
  });

  it('falls back to the header', () => {
    expect(readClientSession({ 'x-wd-session': 'abc' })).toBe('abc');
  });

  it('is undefined when neither is present or the value is empty', () => {
    expect(readClientSession({})).toBeUndefined();
    expect(readClientSession({ cookie: 'wd_cs=' })).toBeUndefined();
  });
});

describe('the in-memory store', () => {
  it('round-trips a verdict', () => {
    const store = new MemoryClientSignalStore();
    store.set(verdict());
    expect(store.get('s1')?.score).toBe(0.9);
  });

  it('expires', () => {
    const store = new MemoryClientSignalStore({ ttl: 10 });
    store.set(verdict({ at: Date.now() - 1000 }));
    expect(store.get('s1')).toBeUndefined();
  });

  it('is bounded', () => {
    const store = new MemoryClientSignalStore({ max: 2 });
    store.set(verdict({ sessionId: 'a' }));
    store.set(verdict({ sessionId: 'b' }));
    store.set(verdict({ sessionId: 'c' }));
    expect(store.size).toBe(2);
    expect(store.get('a')).toBeUndefined();
  });
});

describe('the clientSignals rule', () => {
  it('denies a session the engine called a bot', () => {
    const store = new MemoryClientSignalStore();
    store.set(verdict());
    const result = clientSignals({ store }).evaluate(ctx(withSession('s1')));
    expect(result.action).toBe('DENY');
    expect(result.reason).toMatch(/0\.90/);
  });

  it('allows a session that scored human', () => {
    const store = new MemoryClientSignalStore();
    store.set(verdict({ score: 0.1, recommendation: 'allow' }));
    expect(clientSignals({ store }).evaluate(ctx(withSession('s1'))).action).toBe('ALLOW');
  });

  it('honours an explicit minScore over the engine recommendation', () => {
    const store = new MemoryClientSignalStore();
    store.set(verdict({ score: 0.4, recommendation: 'allow' }));
    expect(clientSignals({ store }).evaluate(ctx(withSession('s1'))).action).toBe('ALLOW');
    expect(
      clientSignals({ store, minScore: 0.3 }).evaluate(ctx(withSession('s1'))).action,
    ).toBe('DENY');
  });

  it('is NOT_RUN for a request with no browser session', () => {
    // A curl request and a search crawler both send nothing. Scoring silence
    // would deny exactly the crawlers we most need to keep.
    const result = clientSignals({ store: new MemoryClientSignalStore() }).evaluate(ctx());
    expect(result.action).toBe('ALLOW');
    expect(result.state).toBe('NOT_RUN');
    expect(result.reason).toMatch(/did not run/);
  });

  it('is NOT_RUN when the session has submitted nothing yet', () => {
    const result = clientSignals({ store: new MemoryClientSignalStore() }).evaluate(
      ctx(withSession('unknown')),
    );
    expect(result.state).toBe('NOT_RUN');
    expect(result.reason).toMatch(/No signals recorded/);
  });

  it('honours dryRun', () => {
    const store = new MemoryClientSignalStore();
    store.set(verdict());
    const result = clientSignals({ store, dryRun: true }).evaluate(ctx(withSession('s1')));
    expect(result.action).toBe('ALLOW');
    expect(result.metadata?.dryRun).toBe(true);
  });
});

describe('an async store', () => {
  function asyncStore(): ClientSignalStore {
    const inner = new MemoryClientSignalStore();
    return {
      sync: false,
      async get(id) {
        await Promise.resolve();
        return inner.get(id);
      },
      async set(v) {
        await Promise.resolve();
        inner.set(v);
      },
    };
  }

  it('is resolved during the async pre-fetch', async () => {
    const store = asyncStore();
    await store.set(verdict());
    const wd = createTestHarness({ rules: [clientSignals({ store })] });
    expectDenied(await wd.protect(request({ headers: withSession('s1') })), {
      rule: 'client-signals',
    });
  });

  it('allows a session the store has nothing for', async () => {
    const wd = createTestHarness({ rules: [clientSignals({ store: asyncStore() })] });
    const d = await wd.protect(request({ headers: withSession('nope') }));
    expectAllowed(d);
    expectRuleState(d, 'client-signals', 'NOT_RUN');
  });
});

describe('the /score endpoint records the verdict', () => {
  it('joins the submission to the requests that follow it', async () => {
    // This is the gap the feature closes: the score used to go back to the
    // browser and the origin never learned anything from it.
    const store = new MemoryClientSignalStore();
    const endpoints = createCaptchaEndpoints({ secret: 'test-secret-value', signalStore: store });

    const response = await endpoints.handle({
      method: 'POST',
      pathname: '/__webdecoy/score',
      query: {},
      headers: { 'user-agent': 'HeadlessChrome/124.0' },
      ip: '203.0.113.9',
      body: {
        sessionId: 'sess-42',
        signals: {
          environmental: { webdriver: true, automationFlags: { plugins: 0 } },
          behavioral: { totalPoints: 0, trajectoryLength: 0 },
        },
      },
    });

    expect(response?.status).toBe(200);
    // Echoed so the widget can set the cookie the rule reads.
    expect((response?.body as { sessionId?: string }).sessionId).toBe('sess-42');

    const recorded = store.get('sess-42');
    expect(recorded).toBeDefined();
    expect(recorded?.score).toBeGreaterThan(0);

    // And the very next request through the SDK acts on it.
    const wd = createTestHarness({ rules: [clientSignals({ store, minScore: 0.01 })] });
    expectDenied(await wd.protect(request({ headers: withSession('sess-42') })), {
      rule: 'client-signals',
    });
  });

  it('records nothing when no store is configured, as before', async () => {
    const endpoints = createCaptchaEndpoints({ secret: 'test-secret-value' });
    const response = await endpoints.handle({
      method: 'POST',
      pathname: '/__webdecoy/score',
      query: {},
      headers: {},
      ip: '203.0.113.9',
      body: { sessionId: 'sess-1', signals: {} },
    });
    expect(response?.status).toBe(200);
  });
});
