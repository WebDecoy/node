import { WebDecoyClient, toWireDetectionRequest } from './client';
import { CREDENTIAL_HEADER, reportableHeaders } from './report-headers';
import type { SDKDetectionRequest } from './types';

function request(headers: Record<string, string>): SDKDetectionRequest {
  return {
    request_metadata: { method: 'GET', path: '/', ip: '203.0.113.7', headers, timestamp: 0 },
    local_analysis: {
      suspicious_headers: false,
      missing_sec_ch_ua: false,
      datacenter_ip: false,
      local_score: 0,
      needs_verification: true,
      flags: [],
    },
  };
}

// What the Express, Fastify, Next.js and Hono adapters hand the SDK: the
// request's full header map, lowercased.
const visitor = {
  'user-agent': 'Mozilla/5.0',
  accept: 'text/html',
  cookie: 'sid=visitor-session; wd_clearance=v1.token; theme=dark',
  authorization: 'Bearer visitor-token',
  'proxy-authorization': 'Basic dXNlcjpwYXNz',
  'x-api-key': 'k_live_123',
  'x-csrf-token': 'c',
  'x-hasura-admin-secret': 's',
  'x-middleware-subrequest': 'middleware',
  'signature-agent': '"https://agent.example"',
};

describe('credential headers in detection reports', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it('never sends a credential value, and keeps every name', async () => {
    let body = '';
    global.fetch = jest.fn(async (_url: any, init: any) => {
      body = init.body;
      return new Response(
        JSON.stringify({
          decision: 'allow',
          confidence: 0,
          threat_level: 'MINIMAL',
          bot_detected: false,
          detection_id: 'd-1',
          rule_enforced: false,
        }),
        { status: 200 },
      );
    }) as any;
    const client = new WebDecoyClient({
      apiKey: 'sk_test_key',
      apiUrl: 'https://ingest.example',
      timeout: 1000,
      debug: false,
      tlsRejectUnauthorized: true,
    });
    await client.detect(request({ ...visitor }));

    for (const secret of [
      'visitor-session',
      'visitor-token',
      'dXNlcjpwYXNz',
      'k_live_123',
      'theme=dark',
    ]) {
      expect(body).not.toContain(secret);
    }
    const sent = JSON.parse(body).request_metadata.headers;
    expect(Object.keys(sent).sort()).toEqual(Object.keys(visitor).sort());
    expect(sent['user-agent']).toBe('Mozilla/5.0');
    expect(sent['x-middleware-subrequest']).toBe('middleware');
    expect(sent['signature-agent']).toBe('"https://agent.example"');
  });

  it("keeps WebDecoy's own clearance cookie and nothing else", () => {
    expect(reportableHeaders({ cookie: 'a=1; wd_clearance=v1.tok=en; b=2' }).cookie).toBe(
      'wd_clearance=v1.tok=en'
    );
    expect(reportableHeaders({ Cookie: 'sid=1' }).Cookie).toBe('');
    expect(reportableHeaders({ cookie: 'not_wd_clearance=x' }).cookie).toBe('');
  });

  it('leaves the request the rules see untouched', () => {
    const req = request({ ...visitor });
    toWireDetectionRequest(req);
    expect(req.request_metadata.headers).toEqual(visitor);
  });

  it('matches credential names, not the evidence', () => {
    for (const name of [
      'Cookie',
      'set-cookie',
      'authorization',
      'x-auth-token',
      'x-vault-token',
      'apikey',
      'x-session-id',
    ]) {
      expect(CREDENTIAL_HEADER.test(name)).toBe(true);
    }
    for (const name of [
      'user-agent',
      'accept',
      'referer',
      'x-forwarded-for',
      'sec-ch-ua',
      'signature',
      'next-action',
    ]) {
      expect(CREDENTIAL_HEADER.test(name)).toBe(false);
    }
  });
});
