/**
 * Pins the TLS info field names to what the detection service parses.
 * The service's struct tag is `alpn`; a differently named key is silently
 * dropped by its JSON decoder, so a rename here would lose the signal with no
 * error anywhere.
 */

import { WebDecoyClient, toWireDetectionRequest } from './client';
import type { SDKDetectionRequest, TLSInfo } from './types';

function request(tls: TLSInfo): SDKDetectionRequest {
  return {
    request_metadata: {
      method: 'GET',
      path: '/',
      ip: '203.0.113.7',
      headers: {},
      tls_info: tls,
      timestamp: 0,
    },
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

describe('tls_info on the wire', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  async function sent(tls: TLSInfo): Promise<Record<string, unknown>> {
    let body: any;
    global.fetch = jest.fn(async (_url: any, init: any) => {
      body = JSON.parse(init.body);
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
    await client.detect(request(tls));
    return body.request_metadata.tls_info;
  }

  it('sends ALPN as `alpn`, the name the service reads', async () => {
    const tls = await sent({ cipher_suites: [4865], alpn: ['h2', 'http/1.1'] });
    expect(tls.alpn).toEqual(['h2', 'http/1.1']);
    expect(tls).not.toHaveProperty('alpn_protocols');
  });

  it('sends the deprecated `alpn_protocols` input as `alpn`', async () => {
    const tls = await sent({ cipher_suites: [4865], alpn_protocols: ['h2'] });
    expect(tls.alpn).toEqual(['h2']);
    expect(tls).not.toHaveProperty('alpn_protocols');
  });

  it('prefers `alpn` when both names are given', () => {
    const wire = toWireDetectionRequest(request({ alpn: ['h2'], alpn_protocols: ['http/1.1'] }));
    expect(wire.request_metadata.tls_info).toEqual({ alpn: ['h2'] });
  });

  it('leaves a request without the deprecated name untouched', () => {
    const req = request({ cipher_suites: [4865], alpn: ['h2'] });
    expect(toWireDetectionRequest(req)).toBe(req);
  });
});
