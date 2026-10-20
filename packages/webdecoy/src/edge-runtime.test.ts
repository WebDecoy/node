/**
 * Edge Runtime execution test.
 *
 * Bundles the SDK for the browser platform (where Node built-ins do not
 * resolve) and executes the keyless middleware path inside Vercel's Edge
 * Runtime VM — the same environment as Vercel Edge Middleware. A Node-only
 * API anywhere in the bundle fails the build step; a runtime dependency on a
 * Node global fails the evaluate step.
 */

import path from 'path';
import { buildSync } from 'esbuild';
import { EdgeVM } from '@edge-runtime/vm';

describe('Edge Runtime compatibility', () => {
  function bundleForEdge(): string {
    const built = buildSync({
      entryPoints: [path.join(__dirname, 'index.ts')],
      bundle: true,
      write: false,
      platform: 'browser',
      format: 'cjs',
      logLevel: 'silent',
    });
    return built.outputFiles[0].text;
  }

  it('bundles without Node built-ins and runs keyless protect() in an Edge VM', async () => {
    const bundle = bundleForEdge();

    const vm = new EdgeVM();
    vm.evaluate('var module = { exports: {} }; var exports = module.exports;');
    vm.evaluate(bundle);

    const result = await vm.evaluate<
      Promise<{
        firstAllowed: boolean;
        thirdAllowed: boolean;
        tripwireAllowed: boolean;
        honeytokenPathOk: boolean;
      }>
    >(`
      (async () => {
        const { WebDecoy, rateLimit, tripwire, honeytoken } = module.exports;
        const hp = honeytoken();
        const sdk = new WebDecoy({
          rules: [rateLimit({ max: 2, window: 60 }), tripwire({ paths: [hp.path] })],
        });
        const meta = {
          method: 'GET',
          path: '/',
          ip: '1.2.3.4',
          headers: { 'user-agent': 'test' },
          timestamp: Date.now(),
        };
        const r1 = await sdk.protect(meta);
        await sdk.protect(meta);
        const r3 = await sdk.protect(meta);
        const trip = await sdk.protect({ ...meta, path: hp.path });
        await sdk.destroy(); // clear the rate-limiter interval so jest can exit
        return {
          firstAllowed: r1.allowed,
          thirdAllowed: r3.allowed,
          tripwireAllowed: trip.allowed,
          honeytokenPathOk: hp.path.startsWith('/__wd/'),
        };
      })()
    `);

    expect(result.firstAllowed).toBe(true);
    expect(result.thirdAllowed).toBe(false); // rate limit max=2 exceeded
    expect(result.tripwireAllowed).toBe(false); // honeytoken path tripped
    expect(result.honeytokenPathOk).toBe(true);
  });

  it('verifies a Web Bot Auth signature via detectBot() in an Edge VM', async () => {
    // Generate a key and sign a request in the Node test context, then verify
    // it entirely inside the Edge VM (WebCrypto Ed25519 + directory cache).
    const enc = new TextEncoder();
    const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const dirJwk = { kty: 'OKP', crv: 'Ed25519', x: pub.x };

    const digest = await crypto.subtle.digest(
      'SHA-256',
      enc.encode(`{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(pub.x)}}`),
    );
    const keyid = Buffer.from(new Uint8Array(digest))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const created = Math.floor(Date.now() / 1000);
    const sigParams = `("@authority");created=${created};expires=${created + 300};keyid="${keyid}";tag="web-bot-auth"`;
    const base = `"@authority": bot.example\n"@signature-params": ${sigParams}`;
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, enc.encode(base));
    const sigHeader = `sig1=:${Buffer.from(new Uint8Array(sig)).toString('base64')}:`;
    const sigInput = `sig1=${sigParams}`;

    const bundle = bundleForEdge();
    const vm = new EdgeVM();
    vm.evaluate('var module = { exports: {} }; var exports = module.exports;');
    vm.evaluate(bundle);

    const result = await vm.evaluate<Promise<{ status: string; name: string | undefined }>>(`
      (async () => {
        const { createAgentVerifier } = module.exports;
        const dirJwk = ${JSON.stringify(dirJwk)};
        const verifier = createAgentVerifier({
          directories: [{ name: 'EdgeBot', category: 'ai_crawlers', directory: 'https://bot.example' }],
          fetchImpl: async () => new Response(JSON.stringify({ keys: [dirJwk] }), { status: 200 }),
        });
        const req = new Request('https://bot.example/foo', {
          headers: {
            'signature-input': ${JSON.stringify(sigInput)},
            'signature': ${JSON.stringify(sigHeader)},
          },
        });
        const verdict = await verifier.verify(req);
        return { status: verdict.status, name: verdict.agentName };
      })()
    `);

    expect(result.status).toBe('verified');
    expect(result.name).toBe('EdgeBot');
  });

  it('captcha token issue/verify works in an Edge VM (Web Crypto path)', async () => {
    const bundle = bundleForEdge();

    const vm = new EdgeVM();
    vm.evaluate('var module = { exports: {} }; var exports = module.exports;');
    vm.evaluate(bundle);

    const result = await vm.evaluate<
      Promise<{ valid: boolean; replayReason: string | undefined; score: number | undefined }>
    >(`
      (async () => {
        const { TokenManager } = module.exports;
        const tm = new TokenManager({ secret: 'edge-test-secret' });
        const token = await tm.issue('1.2.3.4', 'site', 0.25);
        const v = await tm.verify(token, '1.2.3.4');
        const replay = await tm.verify(token, '1.2.3.4');
        return { valid: v.valid, replayReason: replay.reason, score: v.score };
      })()
    `);

    expect(result.valid).toBe(true);
    expect(result.score).toBe(0.25);
    expect(result.replayReason).toBe('token_already_used');
  });
  it('runs the Vercel clearance middleware in an Edge VM: challenge without a token, pass with one', async () => {
    const built = buildSync({
      entryPoints: [path.join(__dirname, 'vercel.ts')],
      bundle: true,
      write: false,
      platform: 'browser',
      format: 'cjs',
      logLevel: 'silent',
    });

    // A real Ed25519 token, minted here and verified inside the VM.
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const pub = Buffer.from(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))).toString('base64');
    const b64url = (b: Uint8Array) =>
      Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = new TextEncoder().encode(
      JSON.stringify({ kid: 'k1', tenant: 'org-1', fp: 'wdfp1-x', exp: Math.floor(Date.now() / 1000) + 600 })
    );
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, payload));
    const token = `${b64url(payload)}.${b64url(sig)}`;
    const config = {
      mode: 'enforce',
      allow: { search_engines: true, ai_crawlers: true, monitoring: true },
      keys: [{ kid: 'k1', public_key: pub }],
      active_credentials: [],
      denied_fps: [],
      generated_at: 0,
      routes: ['/docs/*'],
    };

    const vm = new EdgeVM();
    vm.evaluate('var module = { exports: {} }; var exports = module.exports;');
    vm.evaluate(built.outputFiles[0].text);
    // The verdict telemetry's delayed flush would otherwise hold jest open
    // (on Vercel, waitUntil keeps it alive past the response), so the VM's
    // timers are tracked and cleared once the test has its answer.
    vm.evaluate(`(() => { const realSetTimeout = globalThis.setTimeout;
      globalThis.__wdTimers = [];
      globalThis.setTimeout = (f, ms, ...a) => { const t = realSetTimeout(f, ms, ...a); globalThis.__wdTimers.push(t); return t; };
      // The stubbed fetch answers at once; a real 3 s abort timer would outlive the test.
      AbortSignal.timeout = () => new AbortController().signal; })();`);
    vm.evaluate(`globalThis.fetch = async (u) => String(u).includes('/api/v1/clearance/config')
      ? new Response(${JSON.stringify(JSON.stringify(config))}, { status: 200 })
      : new Response('{}', { status: 200 });`);

    const result = await vm.evaluate<Promise<{ challenged: number | null; passed: string | null }>>(`
      (async () => {
        const mw = module.exports.clearanceMiddleware({ siteKey: 'org-1', scannerId: 's-1', sensorKey: 'wds1.x' });
        const ua = 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';
        const a = await mw(new Request('https://edge.example/docs/a', { headers: { accept: 'text/html', 'user-agent': ua } }));
        const b = await mw(new Request('https://edge.example/docs/a', {
          headers: { accept: 'text/html', 'user-agent': ua, cookie: 'wd_clearance=${token}' },
        }));
        return { challenged: a ? a.status : null, passed: b ? b.headers.get('x-middleware-request-x-wd-clearance') : null };
      })()
    `);

    vm.evaluate('for (const t of globalThis.__wdTimers) clearTimeout(t);');

    expect(result.challenged).toBe(403);
    expect(result.passed).toBe('valid');
  });
});
