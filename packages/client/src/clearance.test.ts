/**
 * @jest-environment jsdom
 *
 * Locks the wd_clearance device-fp contract (#128). The fp is the deny-list key,
 * so its exact composition MUST stay byte-identical to the edge challenge page
 * (app repo: edge/clearance-worker). This test pins the canonical string, a golden
 * hash the worker can cross-assert, and the no-canvas/WebGL guarantee.
 */

import { webcrypto } from 'node:crypto';
import { TextEncoder } from 'node:util';
import { computeDeviceFP, FP_VERSION } from './clearance';
import { sha256 } from './sha256';

// jsdom lacks WebCrypto + TextEncoder; use Node's so sha256() works.
if (!(globalThis.crypto && globalThis.crypto.subtle)) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
}
if (typeof globalThis.TextEncoder === 'undefined') {
  (globalThis as unknown as { TextEncoder: typeof TextEncoder }).TextEncoder = TextEncoder;
}

const FIXTURE = {
  canvasHash: { supported: true, hash: '1a2b3c' },
  webglInfo: { supported: true, renderer: 'ANGLE (Apple M1)', vendor: 'Google Inc.' },
};

// GOLDEN VECTOR — the edge challenge page must produce THIS hash for the same
// inputs (canvas32='1a2b3c', webgl='ANGLE (Apple M1)~Google Inc.',
// screen=1920x1080x24, tz=America/New_York, platform=MacIntel, language=en-US).
const GOLDEN_FP = 'f233cd174fddc4481c658d1c91cb7f2565f325c106355760403f2193f9a681da';

function stubEnv(): void {
  for (const [k, v] of [['width', 1920], ['height', 1080], ['colorDepth', 24]] as const) {
    Object.defineProperty(screen, k, { value: v, configurable: true });
  }
  Object.defineProperty(navigator, 'platform', { value: 'MacIntel', configurable: true });
  Object.defineProperty(navigator, 'language', { value: 'en-US', configurable: true });
  jest
    .spyOn(Intl, 'DateTimeFormat')
    .mockReturnValue({ resolvedOptions: () => ({ timeZone: 'America/New_York' }) } as never);
}

afterEach(() => jest.restoreAllMocks());

describe('computeDeviceFP contract', () => {
  it('matches the independently-built canonical string (locks version/order/format)', async () => {
    stubEnv();
    const expected = await sha256(
      [FP_VERSION, '1a2b3c', 'ANGLE (Apple M1)~Google Inc.', '1920x1080x24', 'America/New_York', 'MacIntel', 'en-US'].join('|'),
    );
    expect(await computeDeviceFP(FIXTURE)).toBe(expected);
  });

  it('produces the golden hash the edge challenge page must match', async () => {
    stubEnv();
    expect(await computeDeviceFP(FIXTURE)).toBe(GOLDEN_FP);
  });

  it('does NO canvas/WebGL work of its own (consumes collector output only)', async () => {
    stubEnv();
    const spy = jest.spyOn(document, 'createElement');
    await computeDeviceFP(FIXTURE);
    const madeCanvas = spy.mock.calls.some((c) => String(c[0]).toLowerCase() === 'canvas');
    expect(madeCanvas).toBe(false);
  });

  it('degrades to "na" for unsupported canvas/WebGL without throwing', async () => {
    stubEnv();
    const fp = await computeDeviceFP({ canvasHash: { supported: false }, webglInfo: { supported: false } });
    const expected = await sha256(
      [FP_VERSION, 'na', 'na', '1920x1080x24', 'America/New_York', 'MacIntel', 'en-US'].join('|'),
    );
    expect(fp).toBe(expected);
  });
});
