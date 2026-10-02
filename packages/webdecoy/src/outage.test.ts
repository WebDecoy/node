/**
 * Behavior while WebDecoy is refusing work or not answering.
 *
 * Every call goes through one client, which pauses after a 429, a 5xx or no
 * answer (honouring Retry-After). While paused, calls fail at once without
 * touching the network, so a request never waits out the timeout on a dead
 * service; buffers stay bounded; and the operator's log gets the failure once,
 * not once per request.
 */

import { WebDecoy } from './sdk';
import { WebDecoyClient, WebDecoyUnavailableError } from './client';
import { ViolationReporter, MAX_BUFFERED_VIOLATIONS } from './violation-reporter';
import { AIReferralCounter } from './referrals/referral-counter';
import { IPEnrichmentClient, MAX_ENRICHMENT_ENTRIES } from './ip-enrichment';
import type { RequestMetadata } from './types';

const realFetch = global.fetch;
let calls = 0;
function serve(answer: () => Response | Promise<Response>) {
  calls = 0;
  global.fetch = jest.fn(async () => {
    calls++;
    return answer();
  }) as any;
}

function client() {
  return new WebDecoyClient({ apiKey: 'k', apiUrl: 'https://ingest.example', timeout: 5000, debug: false, tlsRejectUnauthorized: true });
}

const okDetection = () =>
  new Response(
    JSON.stringify({ decision: 'allow', confidence: 0, threat_level: 'MINIMAL', bot_detected: false, detection_id: 'd', rule_enforced: false }),
    { status: 200 },
  );

beforeEach(() => {
  jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] });
  jest.setSystemTime(new Date('2026-10-02T12:00:00Z'));
});
afterEach(() => {
  global.fetch = realFetch;
  jest.useRealTimers();
});

describe('client pause', () => {
  it('pauses after a 503: the next call fails at once without a request', async () => {
    const c = client();
    serve(() => new Response('', { status: 503 }));
    await expect(c.getIPEnrichment('198.51.100.1')).resolves.toBeNull();
    expect(c.isAvailable()).toBe(false);
    await expect(c.detect({ request_metadata: {} } as any)).rejects.toBeInstanceOf(WebDecoyUnavailableError);
    expect(calls).toBe(1);
  });

  it('honours Retry-After on a 429', async () => {
    const c = client();
    serve(() => new Response('', { status: 429, headers: { 'retry-after': '30' } }));
    await c.getIPEnrichment('198.51.100.1');
    jest.setSystemTime(Date.now() + 29_000);
    expect(c.isAvailable()).toBe(false);
    jest.setSystemTime(Date.now() + 2_000);
    expect(c.isAvailable()).toBe(true);
  });

  it('backs off exponentially when nothing answers, and a success resets it', async () => {
    const c = client();
    serve(() => {
      throw new TypeError('fetch failed');
    });
    await c.getIPEnrichment('a'); // pause 1s
    jest.setSystemTime(Date.now() + 1_001);
    await c.getIPEnrichment('b'); // pause 2s
    jest.setSystemTime(Date.now() + 1_500);
    expect(c.isAvailable()).toBe(false);
    jest.setSystemTime(Date.now() + 600);
    serve(okDetection);
    await c.getIPEnrichment('c');
    expect(c.isAvailable()).toBe(true);
  });

  it('a 4xx answer is not an outage', async () => {
    const c = client();
    serve(() => new Response('{"error":"bad"}', { status: 400 }));
    await c.getIPEnrichment('a');
    expect(c.isAvailable()).toBe(true);
  });
});

describe('protect() during an outage', () => {
  const bot: RequestMetadata = {
    method: 'GET',
    path: '/',
    ip: '203.0.113.9',
    user_agent: 'python-requests/2.31.0',
    headers: { 'user-agent': 'python-requests/2.31.0' },
    timestamp: Date.now(),
  };

  it('fails open without waiting, and logs the outage once, not per request', async () => {
    const errors: string[] = [];
    const logger = { debug() {}, info() {}, warn() {}, error: (m: string) => errors.push(m) };
    const wd = new WebDecoy({ apiKey: 'sk_test_outage', apiUrl: 'https://ingest.example', logger } as any);
    serve(() => new Response('', { status: 503 }));
    const decisions = [];
    for (let i = 0; i < 10; i++) decisions.push(await wd.protect({ ...bot, ip: `203.0.113.${i + 10}` }));
    expect(decisions.every((d) => d.conclusion === 'ERROR')).toBe(true);
    expect(calls).toBe(1);
    expect(errors).toHaveLength(1);
  });
});

describe('bounded buffers', () => {
  it('holds violations while paused, capped, and sends them once WebDecoy is back', async () => {
    const c = client();
    serve(() => new Response('', { status: 503 }));
    await c.getIPEnrichment('a'); // paused
    const reporter = new ViolationReporter(c, { flushInterval: 3_600_000, maxBufferSize: 1_000_000 });
    for (let i = 0; i < MAX_BUFFERED_VIOLATIONS + 500; i++) reporter.report([{ rule: 'r', ip: String(i) } as any]);
    await reporter.flush();
    expect(calls).toBe(1); // nothing sent while paused
    jest.setSystemTime(Date.now() + 2_000);
    const sent: number[] = [];
    global.fetch = jest.fn(async (_u: any, init: any) => {
      sent.push(JSON.parse(init.body).events.length);
      return new Response('{}', { status: 202 });
    }) as any;
    await reporter.destroy();
    expect(sent.reduce((a, b) => a + b, 0)).toBe(MAX_BUFFERED_VIOLATIONS);
  });

  it('keeps an AI referral batch refused with 429, and stops adding pairs past the cap', async () => {
    const batches: any[] = [];
    let ok = false;
    const counter = new AIReferralCounter({
      async sendAIReferrals(b) {
        batches.push(b);
        return ok;
      },
    }, { flushInterval: 3_600_000 });
    const visit = (path: string) =>
      counter.observe({
        method: 'GET',
        path,
        ip: '1.1.1.1',
        headers: { 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', referer: 'https://chatgpt.com/' },
        timestamp: Date.now(),
      });
    visit('/a');
    await counter.flush(); // refused: kept as pending
    for (let i = 0; i < 2_000; i++) visit(`/p${i}`);
    await new Promise((r) => setImmediate(r));
    expect(batches).toHaveLength(1); // no send per new pair while one is pending
    ok = true;
    await counter.flush(); // the pending batch, same id
    await counter.flush(); // what was counted meanwhile
    expect(batches[1].report_id).toBe(batches[0].report_id);
    expect(batches[2].referrals.length).toBeLessThanOrEqual(500);
    await counter.destroy();
  });

  it('a 429 on AI referrals is not treated as delivered', async () => {
    const c = client();
    serve(() => new Response('', { status: 429 }));
    await expect(c.sendAIReferrals({ report_id: 'x', source: 'sdk', referrals: [] })).resolves.toBe(false);
  });

  it('caps the IP enrichment cache', async () => {
    const c = client();
    serve(() => new Response(JSON.stringify({ security: {} }), { status: 200 }));
    const e = new IPEnrichmentClient(c);
    for (let i = 0; i < MAX_ENRICHMENT_ENTRIES + 50; i++) await e.enrich(`10.0.${i >> 8}.${i & 255}`);
    expect((e as any).cache.size).toBe(MAX_ENRICHMENT_ENTRIES);
  });
});
