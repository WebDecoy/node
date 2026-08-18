/**
 * The reserved test trigger: `curl -A "WebDecoy-Test/1.0" <site>` must always
 * report a detection through the normal ingest path — before rules, before
 * local-analysis thresholds — so a fresh install can prove itself from
 * localhost. See docs quickstarts.
 */

import { WebDecoy } from './sdk';
import { isTestTriggerUserAgent, TEST_TRIGGER_USER_AGENT } from './test-trigger';
import { rateLimit } from './rules';
import type { RequestMetadata } from './types';

function metadata(userAgent?: string): RequestMetadata {
  return {
    method: 'GET',
    path: '/',
    ip: '203.0.113.7',
    user_agent: userAgent,
    headers: userAgent ? { 'user-agent': userAgent } : {},
    timestamp: Date.now(),
  };
}

describe('isTestTriggerUserAgent', () => {
  it('matches the documented UA, case-insensitively, prefix-anchored', () => {
    expect(isTestTriggerUserAgent(TEST_TRIGGER_USER_AGENT)).toBe(true);
    expect(isTestTriggerUserAgent('webdecoy-test/2.1')).toBe(true);
    expect(isTestTriggerUserAgent('  WebDecoy-Test/1.0')).toBe(true);

    expect(isTestTriggerUserAgent(undefined)).toBe(false);
    expect(isTestTriggerUserAgent('')).toBe(false);
    expect(isTestTriggerUserAgent('WebDecoy-Test')).toBe(false);
    expect(isTestTriggerUserAgent('Mozilla/5.0 (compatible; WebDecoy-Test/1.0)')).toBe(false);
  });
});

describe('protect() on the test trigger', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it('reports to ingest and returns the server verdict as blocked', async () => {
    const calls: Array<{ url: string; body: any }> = [];
    global.fetch = jest.fn(async (url: any, init: any) => {
      calls.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response(
        JSON.stringify({
          decision: 'block',
          confidence: 100,
          threat_level: 'CRITICAL',
          bot_detected: true,
          bot_type: 'test_trigger',
          detection_id: 'd-123',
          rule_enforced: false,
        }),
        { status: 200 },
      );
    }) as any;

    const sdk = new WebDecoy({ apiKey: 'sk_test_key', apiUrl: 'https://ingest.example' });
    const result = await sdk.protect(metadata(TEST_TRIGGER_USER_AGENT));

    expect(result.allowed).toBe(false);
    expect(result.detection.detection_id).toBe('d-123');
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://ingest.example/api/v1/sdk/detect');
    expect(calls[0].body.local_analysis.flags).toEqual(['test_trigger']);
    expect(calls[0].body.local_analysis.local_score).toBe(100);
    expect(calls[0].body.request_metadata.user_agent).toBe(TEST_TRIGGER_USER_AGENT);
  });

  it('bypasses rules: a 1-request rate limit never throttles the trigger', async () => {
    global.fetch = jest.fn(async () =>
      new Response(
        JSON.stringify({
          decision: 'block',
          confidence: 100,
          threat_level: 'CRITICAL',
          bot_detected: true,
          detection_id: 'd-1',
          rule_enforced: false,
        }),
        { status: 200 },
      ),
    ) as any;

    const sdk = new WebDecoy({
      apiKey: 'sk_test_key',
      apiUrl: 'https://ingest.example',
      rules: [rateLimit({ max: 1, window: 60 })],
    });

    // Both calls must reach ingest — neither may come back as a rule verdict.
    const first = await sdk.protect(metadata(TEST_TRIGGER_USER_AGENT));
    const second = await sdk.protect(metadata(TEST_TRIGGER_USER_AGENT));
    expect(first.ruleResult).toBeUndefined();
    expect(second.ruleResult).toBeUndefined();
    expect((global.fetch as jest.Mock).mock.calls).toHaveLength(2);
  });

  it('still blocks without an apiKey, but says nothing was reported', async () => {
    const sdk = new WebDecoy({});
    const result = await sdk.protect(metadata(TEST_TRIGGER_USER_AGENT));
    expect(result.allowed).toBe(false);
    expect(result.error).toMatch(/apiKey/);
  });

  it('still blocks when ingest is unreachable, and surfaces the error', async () => {
    global.fetch = jest.fn(async () => {
      throw new TypeError('fetch failed');
    }) as any;

    const sdk = new WebDecoy({ apiKey: 'sk_test_key', apiUrl: 'https://ingest.example' });
    const result = await sdk.protect(metadata(TEST_TRIGGER_USER_AGENT));
    expect(result.allowed).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it('leaves ordinary traffic alone', async () => {
    const sdk = new WebDecoy({});
    const result = await sdk.protect(
      metadata('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'),
    );
    expect(result.allowed).toBe(true);
  });
});
