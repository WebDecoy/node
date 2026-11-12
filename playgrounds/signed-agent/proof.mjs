import { webcrypto } from 'node:crypto';
import { WebDecoy } from '@webdecoy/node';
const encoder = new TextEncoder();
const agentOrigin = 'https://demo-agent.example';
const target = 'https://site.example/products';

async function identity() {
  const pair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const exported = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  // RFC 7638/8037 canonical members, ordered lexicographically. Public key only.
  const jwk = { crv: 'Ed25519', kty: 'OKP', x: exported.x };
  const digest = await webcrypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify(jwk)));
  return { privateKey: pair.privateKey, jwk, keyId: Buffer.from(digest).toString('base64url') };
}

async function signedRequest(id, { expired = false } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const created = expired ? now - 1200 : now;
  const expires = expired ? now - 600 : now + 300;
  const params = `("@method" "@target-uri" "signature-agent");created=${created};expires=${expires};keyid="${id.keyId}";tag="web-bot-auth"`;
  const signatureAgent = `"${agentOrigin}"`;
  const base = `"@method": GET\n"@target-uri": ${target}\n"signature-agent": ${signatureAgent}\n"@signature-params": ${params}`;
  const signature = await webcrypto.subtle.sign('Ed25519', id.privateKey, encoder.encode(base));
  return { method: 'GET', url: target, headers: {
    'signature-agent': signatureAgent,
    'signature-input': `sig1=${params}`,
    signature: `sig1=:${Buffer.from(signature).toString('base64')}:`,
  } };
}

export async function runProof() {
  const trusted = await identity();
  const unknown = await identity();
  let directoryReads = 0;
  const sdk = new WebDecoy({ webBotAuth: {
    directories: [{ name: 'Demo Agent (local fixture)', category: 'monitoring', directory: agentOrigin }],
    toleranceSec: 0,
    // Controlled fixture: supply only our generated public key. No live vendor
    // directory or network is used. The SDK verifier itself is not mocked.
    fetchImpl: async (url) => {
      if (String(url) !== `${agentOrigin}/.well-known/http-message-signatures-directory`) {
        throw new Error(`Unexpected fixture directory: ${String(url)}`);
      }
      directoryReads += 1;
      return new Response(JSON.stringify({ keys: [trusted.jwk] }), {
        headers: { 'content-type': 'application/http-message-signatures-directory+json' },
      });
    },
  } });
  const valid = await signedRequest(trusted);
  const cases = [
    ['valid', valid],
    // Change a covered component after signing; retain the original signature.
    ['tampered', { ...valid, url: 'https://site.example/private' }],
    ['expired', await signedRequest(trusted, { expired: true })],
    ['unknown signer', await signedRequest(unknown)],
    ['unsigned', { method: 'GET', url: target, headers: {} }],
  ];
  const results = [];
  for (const [scenario, request] of cases) {
    const verdict = await sdk.detectBot(request);
    results.push({ scenario, status: verdict.status, reason: verdict.reason ?? null, agent: verdict.agentName ?? null });
  }
  return { sdkVersion: '0.22.3', fixture: 'Generated demo keys; injected public directory; no vendor traffic or external calls', directoryReads, results };
}
