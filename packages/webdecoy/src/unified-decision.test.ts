import { createFetchGuard } from './fetch-guard';
import { tripwire } from './rules';
import { WebDecoy } from './sdk';
import type { RequestMetadata, SDKDetectionResponse, WebDecoyConfig } from './types';

const options = {
  apiKey: 'sk_test_decision_fixture',
  apiUrl: 'https://ingest.example',
  rules: [],
  countAIReferrals: false,
  logger: { debug() {}, info() {}, warn() {}, error() {} },
} satisfies WebDecoyConfig;

const bot: RequestMetadata = {
  method: 'GET',
  path: '/products',
  ip: '192.0.2.9',
  user_agent: 'python-requests/2.31.0',
  headers: { 'user-agent': 'python-requests/2.31.0' },
  timestamp: 1,
};

const browser: RequestMetadata = {
  ...bot,
  user_agent: 'Mozilla/5.0 Firefox/140.0',
  headers: {
    'user-agent': 'Mozilla/5.0 Firefox/140.0',
    accept: 'text/html',
    'accept-language': 'en',
    'accept-encoding': 'gzip',
  },
};

function unified(decision: SDKDetectionResponse['decision']): SDKDetectionResponse {
  const fields = {
    allow: { unified_score: 10, confidence: 20, threat_level: 'MINIMAL' },
    challenge: { unified_score: 55, confidence: 50, threat_level: 'MEDIUM' },
    block: { unified_score: 70, confidence: 70, threat_level: 'HIGH' },
  } as const;
  return {
    ...fields[decision],
    decision_mode: 'unified_v1',
    decision,
    bot_detected: decision !== 'allow',
    detection_id: 'detection-from-ingest',
    rule_enforced: false,
  };
}

function serve(body: unknown, status = 200) {
  return jest.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    new Response(JSON.stringify(body), { status }),
  );
}

afterEach(() => jest.restoreAllMocks());

it('uses the opted-in verdict and exposes the synchronous score on the returned decision', async () => {
  const fetch = serve(unified('block'));
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1' });
  const result = await sdk.protect(bot);
  expect(result.conclusion).toBe('DENY');
  expect(result.detection).toMatchObject({ decision_mode: 'unified_v1', unified_score: 70, confidence: 70 });
  expect(fetch).toHaveBeenCalledTimes(1);
  const wire = JSON.parse(fetch.mock.calls[0][1]?.body as string);
  expect(wire.decision_mode).toBe('unified_v1');
  expect(wire.request_metadata).not.toHaveProperty('tls_info');
});

it('omits the negotiation field and keeps the legacy confidence minimum by default', async () => {
  const { decision_mode, unified_score, ...legacy } = unified('block');
  expect(decision_mode).toBe('unified_v1');
  expect(unified_score).toBe(70);
  const fetch = serve(legacy);
  const result = await new WebDecoy(options).protect(bot);
  expect(result.conclusion).toBe('ALLOW');
  expect(JSON.parse(fetch.mock.calls[0][1]?.body as string)).not.toHaveProperty('decision_mode');
});

it('keeps an explicitly configured confidence minimum and the per-request override', async () => {
  serve(unified('challenge'));
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1', threatScoreThreshold: 60 });
  expect((await sdk.protect(bot)).conclusion).toBe('ALLOW');
  expect((await sdk.protect(bot, { threshold: 50 })).conclusion).toBe('CHALLENGE');
});

it('runs the local gate in unified mode and traces excluded requests without transmitting them', async () => {
  const fetch = serve(unified('allow'));
  const setAttribute = jest.fn();
  const tracer = { startSpan: () => ({ setAttribute, end() {} }) };
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1', tracer });
  expect((await sdk.protect(browser)).conclusion).toBe('ALLOW');
  expect(fetch).not.toHaveBeenCalled();
  expect(setAttribute).toHaveBeenCalledWith('webdecoy.cloud.admission', 'local_gate');
  expect(setAttribute).toHaveBeenCalledWith('webdecoy.cloud.gate_datacenter_ip', false);
  expect(setAttribute).toHaveBeenCalledWith('webdecoy.cloud.gate_missing_sec_ch_ua', true);
});

it('does not reuse a cloud block when the next request takes a different path', async () => {
  const fetch = serve(unified('allow'));
  fetch.mockResolvedValueOnce(new Response(JSON.stringify(unified('block')), { status: 200 }));
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1' });
  expect((await sdk.protect(bot)).conclusion).toBe('DENY');
  expect((await sdk.protect({ ...bot, path: '/help' })).conclusion).toBe('ALLOW');
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('never asks the cloud for a verdict when a local rule already denied', async () => {
  const fetch = serve(unified('allow'));
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1', rules: [tripwire({ paths: ['/local-rule-fixture'] })] });
  try {
    const result = await sdk.protect({ ...bot, path: '/local-rule-fixture' });
    expect(result.conclusion).toBe('DENY');
    expect(result.detection.rule_enforced).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
  } finally {
    await sdk.destroy();
  }
});

it.each([
  ['unavailable', { error: 'unavailable' }, 503],
  ['legacy response', { ...unified('block'), decision_mode: undefined }, 200],
  ['missing unified score', { ...unified('block'), unified_score: undefined }, 200],
  ['unknown action', { ...unified('block'), decision: 'unexpected' }, 200],
])('serves the request and reports an ERROR for %s', async (_name, body, status) => {
  const fetch = serve(body, status);
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1' });
  const decision = await sdk.protect(bot);
  expect(decision.conclusion).toBe('ERROR');
  expect(decision.allowed).toBe(true);
  if (status === 503) {
    expect((await sdk.protect(bot)).conclusion).toBe('ERROR');
    expect(fetch).toHaveBeenCalledTimes(1);
  }
});

it('preserves the installation trigger and sends the opted-in mode', async () => {
  const fetch = serve(unified('block'));
  const sdk = new WebDecoy({ ...options, decisionMode: 'unified_v1' });
  const result = await sdk.protect({ ...bot, user_agent: 'WebDecoy-Test/1.0' });
  expect(result.conclusion).toBe('DENY');
  expect(JSON.parse(fetch.mock.calls[0][1]?.body as string)).toMatchObject({
    decision_mode: 'unified_v1',
    local_analysis: { flags: ['test_trigger'] },
  });
});

it.each([['monitor', undefined], ['enforce', 403]] as const)(
  'fetch guard applies the unified decision in %s mode',
  async (mode, status) => {
    serve(unified('block'));
    const guard = createFetchGuard({ ...options, mode, decisionMode: 'unified_v1' });
    const { decision, response } = await guard.check(new Request('https://shop.example/products', {
      headers: { 'user-agent': bot.user_agent! },
    }));
    expect(decision.conclusion).toBe('DENY');
    expect(response?.status).toBe(status);
  },
);
