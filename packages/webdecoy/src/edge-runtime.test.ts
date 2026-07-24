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
});
