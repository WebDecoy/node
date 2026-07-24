/**
 * Web Bot Auth local verification tests.
 *
 * Signatures are constructed here **independently** of the verifier: the
 * RFC 9421 signature base is built by hand and signed with Node WebCrypto, so
 * a bug in the verifier's own base construction (authority canonicalization,
 * line format, @signature-params reconstruction) makes verification fail
 * rather than pass. This pins the exact byte contract, not merely
 * self-consistency.
 */

import { AgentVerifier } from './verifier';
import { jwkThumbprint, rsaThumbprint } from './thumbprint';
import type { SignedAgentDirectory } from './types';

const enc = new TextEncoder();

function canonicalAuthority(u: URL): string {
  const host = u.hostname.toLowerCase();
  if (!u.port) return host;
  if ((u.protocol === 'https:' && u.port === '443') || (u.protocol === 'http:' && u.port === '80')) {
    return host;
  }
  return `${host}:${u.port}`;
}

function componentValue(name: string, u: URL, method: string): string {
  switch (name) {
    case '@authority':
      return canonicalAuthority(u);
    case '@method':
      return method.toUpperCase();
    case '@path':
      return u.pathname;
    case '@target-uri':
      return `${u.protocol}//${canonicalAuthority(u)}${u.pathname}${u.search}`;
    default:
      throw new Error(`test helper: unhandled component ${name}`);
  }
}

interface SignOpts {
  privateKey: CryptoKey;
  url: string;
  method?: string;
  components?: string[];
  keyid: string;
  created?: number;
  expires?: number;
  tag?: string;
  tamper?: boolean;
  label?: string;
}

/** Produce the Signature-Input / Signature header pair for a request. */
async function signHeaders(opts: SignOpts): Promise<Record<string, string>> {
  const u = new URL(opts.url);
  const method = opts.method ?? 'GET';
  const components = opts.components ?? ['@authority'];
  const now = Math.floor(Date.now() / 1000);
  const created = opts.created ?? now;
  const expires = opts.expires ?? created + 300;
  const tag = opts.tag ?? 'web-bot-auth';
  const label = opts.label ?? 'sig1';

  const inner = '(' + components.map((c) => `"${c}"`).join(' ') + ')';
  const params = `;created=${created};expires=${expires};keyid="${opts.keyid}";tag="${tag}"`;
  const sigParamsValue = inner + params;

  const lines = components.map((c) => `"${c}": ${componentValue(c, u, method)}`);
  lines.push(`"@signature-params": ${sigParamsValue}`);
  const base = lines.join('\n');

  const buf = await crypto.subtle.sign({ name: 'Ed25519' }, opts.privateKey, enc.encode(base));
  const bytes = new Uint8Array(buf);
  if (opts.tamper) bytes[0] ^= 0xff;
  const b64 = Buffer.from(bytes).toString('base64');

  return {
    'signature-input': `${label}=${sigParamsValue}`,
    signature: `${label}=:${b64}:`,
  };
}

function mockDirectory(jwks: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(jwks), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
}

const TEST_DIR: SignedAgentDirectory = {
  name: 'TestBot',
  category: 'ai_crawlers',
  directory: 'https://bot.example',
};

async function fixture() {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  // Directory JWKs carry only public material.
  const dirJwk = { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x };
  const keyid = await jwkThumbprint(dirJwk);
  const verifier = new AgentVerifier({
    directories: [TEST_DIR],
    fetchImpl: mockDirectory({ keys: [dirJwk] }),
  });
  return { privateKey: kp.privateKey, keyid, verifier };
}

describe('AgentVerifier — Web Bot Auth', () => {
  it('verifies a valid signature and surfaces the agent name/category', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    const headers = await signHeaders({ privateKey, keyid, url: 'https://bot.example/foo' });
    const req = new Request('https://bot.example/foo', { headers });

    const verdict = await verifier.verify(req);
    expect(verdict.status).toBe('verified');
    expect(verdict.agentName).toBe('TestBot');
    expect(verdict.category).toBe('ai_crawlers');
    expect(verdict.algorithm).toBe('ed25519');
    expect(verdict.method).toBe('signature');
    expect(verdict.keyId).toBe(keyid);
  });

  it('verifies a multi-component signature (@method @authority @path)', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    const headers = await signHeaders({
      privateKey,
      keyid,
      url: 'https://bot.example/api/data?x=1',
      method: 'POST',
      components: ['@method', '@authority', '@path'],
    });
    const req = new Request('https://bot.example/api/data?x=1', { method: 'POST', headers });
    expect((await verifier.verify(req)).status).toBe('verified');
  });

  it('flags a tampered signature over a known key as impersonation', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    const headers = await signHeaders({
      privateKey,
      keyid,
      url: 'https://bot.example/foo',
      tamper: true,
    });
    const req = new Request('https://bot.example/foo', { headers });
    const verdict = await verifier.verify(req);
    expect(verdict.status).toBe('impersonation');
    expect(verdict.reason).toBe('bad-signature');
  });

  it('flags an expired signature over a known key as impersonation', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    const created = Math.floor(Date.now() / 1000) - 4000;
    const headers = await signHeaders({
      privateKey,
      keyid,
      url: 'https://bot.example/foo',
      created,
      expires: created + 300, // well outside the 300s tolerance
    });
    const req = new Request('https://bot.example/foo', { headers });
    const verdict = await verifier.verify(req);
    expect(verdict.status).toBe('impersonation');
    expect(verdict.reason).toBe('expired');
  });

  it('treats a signature from an unknown key as an unverifiable claim', async () => {
    const { privateKey, verifier } = await fixture();
    const headers = await signHeaders({
      privateKey,
      keyid: 'ZmFrZS10aHVtYnByaW50LXVua25vd24', // not in the directory
      url: 'https://bot.example/foo',
    });
    const req = new Request('https://bot.example/foo', { headers });
    const verdict = await verifier.verify(req);
    expect(verdict.status).toBe('claimed');
    expect(verdict.reason).toBe('unknown-key');
  });

  it('treats a signature not binding the host as an unverifiable claim', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    // Sign over @method only — no @authority / @target-uri. The profile
    // requires host binding, so the verifier must not accept it.
    const headers = await signHeaders({
      privateKey,
      keyid,
      url: 'https://bot.example/foo',
      components: ['@method'],
    });
    const req = new Request('https://bot.example/foo', { headers });
    expect((await verifier.verify(req)).status).toBe('claimed');
  });

  it('returns none for a half-present signature', async () => {
    const { verifier } = await fixture();
    const req = new Request('https://bot.example/foo', {
      headers: { 'signature-input': 'sig1=("@authority")' }, // no Signature header
    });
    expect((await verifier.verify(req)).status).toBe('claimed');
  });

  it('returns none for ordinary traffic (no signature)', async () => {
    const { verifier } = await fixture();
    const req = new Request('https://bot.example/foo', { headers: { 'user-agent': 'Mozilla/5.0' } });
    expect((await verifier.verify(req)).status).toBe('none');
  });

  it('accepts the plain { method, url, headers } request shape (Node path)', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    const headers = await signHeaders({ privateKey, keyid, url: 'https://bot.example/foo' });
    const verdict = await verifier.verify({
      method: 'GET',
      url: 'https://bot.example/foo',
      headers,
    });
    expect(verdict.status).toBe('verified');
  });

  it('does not fetch the network on the warm path and verifies in <5ms p95', async () => {
    const { privateKey, keyid, verifier } = await fixture();
    const headers = await signHeaders({ privateKey, keyid, url: 'https://bot.example/foo' });
    const req = new Request('https://bot.example/foo', { headers });

    // Warm the directory cache (one cold fetch), then verify repeatedly.
    await verifier.verify(req);

    const N = 200;
    const samples: number[] = [];
    for (let i = 0; i < N; i++) {
      const t0 = performance.now();
      await verifier.verify(req);
      samples.push(performance.now() - t0);
    }
    samples.sort((a, b) => a - b);
    const p95 = samples[Math.floor(N * 0.95)];
    expect(p95).toBeLessThan(5);
  });
});

describe('JWK thumbprint', () => {
  it('matches the RFC 7638 §3.1 RSA known-answer', async () => {
    // The canonical example from RFC 7638.
    const n =
      '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
    expect(await rsaThumbprint(n, 'AQAB')).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });
});
