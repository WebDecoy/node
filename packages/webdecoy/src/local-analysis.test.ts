import { analyzeRequest } from './local-analysis';
import type { RequestMetadata } from './types';

// The forwarding contract (#only-bot-traffic): a request only goes to the
// server — and so only reaches ingest — when a genuine local bot signal is
// present. A datacenter/VPN IP is not one on its own, or real sites drown in
// their own legitimate traffic.
describe('analyzeRequest forwarding decision', () => {
  const base = (over: Partial<RequestMetadata> = {}): RequestMetadata =>
    ({
      ip: '3.1.2.3', // inside a datacenter range (3.0.0.0/8)
      method: 'GET',
      path: '/',
      user_agent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0 Safari/537.36',
      headers: {
        'user-agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0 Safari/537.36',
        accept: 'text/html',
        'accept-language': 'en-US',
        'accept-encoding': 'gzip',
        'sec-ch-ua': '"Chromium";v="138"',
        referer: 'https://example.com/',
      },
      ...over,
    }) as RequestMetadata;

  it('does NOT forward a clean browser on a datacenter/VPN IP', () => {
    // This is the exact lowering.tax case: a real Chrome user on a VPN.
    const a = analyzeRequest(base());
    expect(a.datacenter_ip).toBe(true);
    expect(a.suspicious_headers).toBe(false);
    expect(a.needs_verification).toBe(false);
  });

  it('forwards a bot user agent (a genuine local signal)', () => {
    const a = analyzeRequest(base({ user_agent: 'python-requests/2.31', headers: { 'user-agent': 'python-requests/2.31' } }));
    expect(a.suspicious_headers).toBe(true);
    expect(a.needs_verification).toBe(true);
  });

  it('forwards when TLS info is present, for fingerprinting', () => {
    const a = analyzeRequest(base({ tls_info: { ja3: 'abc' } } as Partial<RequestMetadata>));
    expect(a.needs_verification).toBe(true);
  });

  it('does NOT forward a Firefox/Safari user (no Sec-CH-UA) on a VPN', () => {
    const h = base();
    delete (h.headers as Record<string, string>)['sec-ch-ua'];
    const a = analyzeRequest(h);
    expect(a.missing_sec_ch_ua).toBe(true);
    expect(a.datacenter_ip).toBe(true);
    expect(a.needs_verification).toBe(false);
  });
});
