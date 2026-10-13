/**
 * Parity tests for the detection engine, ported from the FCaptcha reference
 * suite (test/test-detection.js). Each case feeds the same signals the reference
 * server receives and asserts the same category detections / score buckets.
 *
 * The reference server hard-fails when no PoW solution is present, so these
 * tests run with the engine default (requirePoW: true); "legitimate" fixtures
 * still land below the 0.3 allow threshold, matching the reference.
 */

import { DetectionEngine } from './engine';
import type { DetectionContext, Signals, Verdict } from './types';

const UA_CHROME_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
const UA_CHROME_MAC =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const UA_IPHONE =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';

interface ScoreOpts {
  ua?: string;
  ip?: string;
  headers?: Record<string, string>;
  ja3Hash?: string;
}

function score(signals: Signals, opts: ScoreOpts = {}): Verdict {
  const engine = new DetectionEngine();
  const ua = opts.ua ?? UA_CHROME_WIN;
  const context: DetectionContext = {
    ip: opts.ip ?? '73.15.22.100', // Comcast residential by default
    siteKey: 'test',
    userAgent: ua,
    headers: { 'user-agent': ua, ...(opts.headers ?? {}) },
    ja3Hash: opts.ja3Hash,
  };
  return engine.score(signals, context);
}

function hasCategory(v: Verdict, category: string): boolean {
  return v.detections.some((d) => d.category === category);
}

function hasReasonIncluding(v: Verdict, fragment: string): boolean {
  return v.detections.some((d) => d.reason.includes(fragment));
}

const GOOD_HEADERS = {
  'accept': 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
};

const HUMAN_BEHAVIOR = {
  totalPoints: 80,
  trajectoryLength: 350,
  velocityVariance: 0.8,
  microTremorScore: 0.6,
  directionChanges: 15,
  mouseEventRate: 60,
  interactionDuration: 1500,
  approachPoints: 12,
  overshootCorrections: 3,
  eventDeltaVariance: 25,
};

const CHROME_MAC_ENV = {
  automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 },
  navigator: { platform: 'MacIntel', maxTouchPoints: 0 },
};

describe('bot User-Agent detection', () => {
  const botUAs = [
    'curl/7.64.1',
    'python-requests/2.28.0',
    'Go-http-client/1.1',
    'axios/1.4.0',
    'node-fetch/3.0.0',
    'Java/11.0.2',
    'Wget/1.21',
    'PostmanRuntime/7.32.0',
    'Googlebot/2.1',
    'Mozilla/5.0 (compatible; bingbot/2.0)',
  ];

  it.each(botUAs)('flags %s as bot', (ua) => {
    expect(hasCategory(score({}, { ua }), 'bot')).toBe(true);
  });
});

describe('headless browser detection', () => {
  it('detects WebDriver flag', () => {
    const v = score({ environmental: { webdriver: true } });
    expect(hasCategory(v, 'headless')).toBe(true);
  });

  it('detects HeadlessChrome UA', () => {
    const v = score({}, { ua: 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0' });
    expect(hasCategory(v, 'headless')).toBe(true);
  });

  it('detects no browser plugins', () => {
    const v = score({ environmental: { automationFlags: { plugins: 0, languages: false } } });
    expect(hasCategory(v, 'headless')).toBe(true);
  });
});

describe('datacenter IP detection', () => {
  const datacenterIPs = [
    '52.1.2.3', '34.102.1.1', '20.1.2.3', '134.209.1.1',
    '45.33.1.1', '45.32.1.1', '95.216.1.1', '51.38.1.1',
  ];

  it.each(datacenterIPs)('flags %s as datacenter', (ip) => {
    expect(hasCategory(score({}, { ip }), 'datacenter')).toBe(true);
  });

  it('does NOT flag residential IP', () => {
    expect(hasCategory(score({}, { ip: '73.15.22.100' }), 'datacenter')).toBe(false);
  });
});

describe('header analysis', () => {
  it('detects missing browser headers', () => {
    // Only user-agent present → 3 expected headers missing.
    const v = score({}, { headers: {} });
    expect(hasCategory(v, 'bot')).toBe(true);
  });

  it('detects invalid Accept-Language', () => {
    const v = score({}, { headers: { 'accept-language': '*' } });
    expect(hasReasonIncluding(v, 'Invalid Accept-Language')).toBe(true);
  });

  it('gives normal headers a low score', () => {
    const v = score({ behavioral: HUMAN_BEHAVIOR }, { ua: UA_CHROME_MAC, headers: GOOD_HEADERS });
    expect(v.score).toBeLessThanOrEqual(0.3);
  });
});

describe('browser consistency', () => {
  it('detects Chrome UA without window.chrome', () => {
    const v = score({ environmental: { automationFlags: { chrome: false, platform: 'Win32' } } });
    expect(hasReasonIncluding(v, 'window.chrome missing')).toBe(true);
  });

  it('detects UA/platform mismatch', () => {
    const v = score({ environmental: { automationFlags: { platform: 'MacIntel', chrome: true } } });
    expect(hasReasonIncluding(v, 'UA/platform mismatch')).toBe(true);
  });

  it('detects mobile UA without touch support', () => {
    const v = score({ environmental: { navigator: { maxTouchPoints: 0 } } }, { ua: UA_IPHONE });
    expect(hasReasonIncluding(v, 'no touch support')).toBe(true);
  });

  it('gives a consistent browser a low score', () => {
    const v = score(
      { behavioral: HUMAN_BEHAVIOR, environmental: CHROME_MAC_ENV },
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(v.score).toBeLessThanOrEqual(0.3);
  });
});

describe('behavioral signals', () => {
  it('gives bot-like behavior a high score', () => {
    const v = score({
      behavioral: {
        interactionDuration: 50,
        velocityVariance: 0.001,
        trajectoryLength: 200,
        totalPoints: 100,
        microTremorScore: 0.05,
        straightLineRatio: 0.95,
        directionChanges: 1,
      },
    });
    expect(v.score).toBeGreaterThanOrEqual(0.3);
  });

  it('gives human-like behavior a low score', () => {
    const v = score(
      { behavioral: HUMAN_BEHAVIOR, environmental: CHROME_MAC_ENV },
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(v.score).toBeLessThanOrEqual(0.3);
  });
});

describe('vision AI detection', () => {
  it('detects impossibly fast PoW', () => {
    const v = score({ temporal: { pow: { duration: 10, iterations: 100000 } } });
    expect(hasCategory(v, 'vision_ai')).toBe(true);
  });

  it('detects slow PoW (external processing)', () => {
    const v = score({ temporal: { pow: { duration: 15000, iterations: 100000 } } });
    expect(hasCategory(v, 'vision_ai')).toBe(true);
  });

  it('detects lack of micro-tremor', () => {
    const v = score({ behavioral: { microTremorScore: 0.05, trajectoryLength: 200 } });
    expect(hasReasonIncluding(v, 'micro-tremor')).toBe(true);
  });
});

describe('form interaction', () => {
  it('detects programmatic form.submit()', () => {
    const v = score({
      formAnalysis: {
        pageLoadToFirstInteraction: 500,
        submit: { method: 'programmatic', timeSincePageLoad: 100, eventsBeforeSubmit: 0 },
      },
    });
    expect(hasReasonIncluding(v, 'programmatically')).toBe(true);
  });

  it('detects zero events before submit', () => {
    const v = score({
      formAnalysis: {
        pageLoadToFirstInteraction: null,
        submit: { method: 'programmatic_click', timeSincePageLoad: 50, eventsBeforeSubmit: 0 },
      },
    });
    expect(hasReasonIncluding(v, 'no user interaction events')).toBe(true);
  });

  it('detects impossibly fast textarea typing', () => {
    const v = score({
      formAnalysis: {
        pageLoadToFirstInteraction: 1000,
        submit: { method: 'keyboard', timeSincePageLoad: 2000, eventsBeforeSubmit: 50 },
        textareaKeyboard: {
          comment: { keyCount: 50, pasteCount: 0, avgKeyInterval: 20, keyIntervalVariance: 50, keydownUpRatio: 1.0 },
        },
      },
    });
    expect(hasReasonIncluding(v, 'impossibly fast')).toBe(true);
  });
});

describe('keystroke cadence', () => {
  function seededRand(seed: number): () => number {
    let s = seed;
    return () => {
      s = (s * 1103515245 + 12345) & 0x7fffffff;
      return s / 0x7fffffff;
    };
  }

  function humanIntervals(n: number): number[] {
    const r = seededRand(42);
    const mu = 4.8;
    const sigma = 0.4;
    const out: number[] = [];
    for (let i = 0; i < n; i++) {
      const u1 = r() || 0.001;
      const u2 = r() || 0.001;
      const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      out.push(Math.max(40, Math.min(500, Math.exp(mu + sigma * z))));
    }
    return out;
  }

  const baseForm = (textareaStats: Record<string, unknown>) => ({
    behavioral: HUMAN_BEHAVIOR,
    environmental: CHROME_MAC_ENV,
    formAnalysis: {
      pageLoadToFirstInteraction: 1500,
      submit: { method: 'keyboard', timeSincePageLoad: 5000, eventsBeforeSubmit: 40 },
      textareaKeyboard: { message: textareaStats },
    },
  });

  it('does not flag human cadence', () => {
    const r = seededRand(42);
    const dwell: number[] = [];
    for (let i = 0; i < 30; i++) dwell.push(25 + r() * 50);
    const v = score(
      baseForm({
        keyCount: 40,
        avgKeyInterval: 130,
        keyIntervalVariance: 3500,
        keydownUpRatio: 1.0,
        pasteCount: 0,
        intervals: humanIntervals(35),
        dwellTimes: dwell,
        rollovers: 8,
      }),
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(hasReasonIncluding(v, 'Keystroke cadence')).toBe(false);
  });

  it('flags constant-timing bot cadence', () => {
    const v = score(
      baseForm({
        keyCount: 40,
        avgKeyInterval: 100,
        keyIntervalVariance: 5,
        keydownUpRatio: 1.0,
        pasteCount: 0,
        intervals: Array(35).fill(100),
        dwellTimes: Array(30).fill(50),
        rollovers: 0,
      }),
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(hasReasonIncluding(v, 'Keystroke cadence')).toBe(true);
  });

  it('does not flag cadence on minimal data', () => {
    const v = score(
      baseForm({
        keyCount: 8,
        avgKeyInterval: 100,
        keyIntervalVariance: 5,
        keydownUpRatio: 1.0,
        pasteCount: 0,
        intervals: [100, 100, 100, 100, 100],
        dwellTimes: [50, 50, 50, 50, 50],
        rollovers: 0,
      }),
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(hasReasonIncluding(v, 'Keystroke cadence')).toBe(false);
  });
});

describe('advanced fingerprint detection', () => {
  it('detects no media devices via WebRTC', () => {
    const v = score({
      environmental: {
        webrtcInfo: {
          supported: true,
          mediaDevices: { supported: true, audioInputs: 0, audioOutputs: 0, videoInputs: 0, totalDevices: 0 },
          hasLocalIP: false,
        },
      },
    });
    expect(hasCategory(v, 'headless')).toBe(true);
  });

  it('detects no speech voices', () => {
    const v = score({ environmental: { speechInfo: { supported: true, totalVoices: 0, localVoices: 0 } } });
    expect(hasReasonIncluding(v, 'speech synthesis voices')).toBe(true);
  });

  it('detects worker/main thread mismatch', () => {
    const v = score({
      environmental: {
        workerConsistency: { supported: true, consistent: false, mismatches: ['userAgent', 'platform'], mismatchCount: 2 },
      },
    });
    expect(hasReasonIncluding(v, 'Worker/main thread mismatch')).toBe(true);
  });

  it('detects Windows UA without Segoe UI', () => {
    const v = score({
      environmental: { fontsInfo: { supported: true, count: 10, hasSegoeUI: false, hasSFPro: false, hasDejaVuSans: false } },
    });
    expect(hasReasonIncluding(v, 'Segoe UI')).toBe(true);
  });

  it('detects CSS pointer/touch mismatch', () => {
    const v = score({
      environmental: {
        cssMediaQueries: { supported: true, pointer: 'coarse', hover: false },
        navigator: { maxTouchPoints: 0 },
      },
    });
    expect(hasReasonIncluding(v, 'coarse pointer')).toBe(true);
  });

  it('detects zero-dimension DOMRect', () => {
    const v = score({
      environmental: { domRectFingerprint: { supported: true, rectAWidth: 0, rectBWidth: 0, rangeWidth: 0 } },
    });
    expect(hasReasonIncluding(v, 'zero-width')).toBe(true);
  });
});

describe('Playwright detection', () => {
  it('detects Playwright globals', () => {
    const v = score(
      { environmental: { playwright: { detected: true, signals: ['playwright_globals'] } } },
      { ua: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0' },
    );
    expect(hasReasonIncluding(v, 'Playwright artifact')).toBe(true);
  });

  it('does not flag a clean browser', () => {
    const v = score(
      { behavioral: HUMAN_BEHAVIOR, environmental: { ...CHROME_MAC_ENV, playwright: { detected: false, signals: [] } } },
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(hasReasonIncluding(v, 'Playwright')).toBe(false);
  });
});

describe('PoW outcome', () => {
  it('hard-fails when no PoW solution provided (default requirePoW)', () => {
    // Clean Mac browser: only the missing-PoW detection fires, contributing
    // bot(0.9) * weight(0.15) = 0.135 to the final score.
    const v = score(
      { behavioral: HUMAN_BEHAVIOR, environmental: CHROME_MAC_ENV },
      { ua: UA_CHROME_MAC, headers: GOOD_HEADERS },
    );
    expect(hasReasonIncluding(v, 'No PoW solution')).toBe(true);
    expect(v.score).toBeGreaterThanOrEqual(0.1);
  });

  it('does not require PoW when disabled', () => {
    const engine = new DetectionEngine({ requirePoW: false });
    const v = engine.score(
      { behavioral: HUMAN_BEHAVIOR, environmental: CHROME_MAC_ENV },
      { ip: '73.15.22.100', siteKey: 'test', userAgent: UA_CHROME_MAC, headers: { 'user-agent': UA_CHROME_MAC, ...GOOD_HEADERS } },
    );
    expect(hasReasonIncluding(v, 'No PoW solution')).toBe(false);
  });

  it('flags a failed PoW verification', () => {
    const engine = new DetectionEngine();
    const v = engine.score(
      {},
      {
        ip: '73.15.22.100',
        siteKey: 'test',
        userAgent: UA_CHROME_WIN,
        headers: { 'user-agent': UA_CHROME_WIN },
        pow: { provided: true, valid: false, reason: 'invalid_hash' },
      },
    );
    expect(hasReasonIncluding(v, 'PoW verification failed: invalid_hash')).toBe(true);
  });

  it('flags challenge solved too fast (server timing)', () => {
    const engine = new DetectionEngine();
    const v = engine.score(
      { meta: { challengeNonce: 'abc' } },
      {
        ip: '73.15.22.100',
        siteKey: 'test',
        userAgent: UA_CHROME_WIN,
        headers: { 'user-agent': UA_CHROME_WIN },
        pow: { provided: true, valid: true, nonce: 'abc', serverElapsed: 200 },
      },
    );
    expect(hasReasonIncluding(v, 'solved too fast')).toBe(true);
  });
});

describe('accessibility exemptions', () => {
  it('does not exempt touchEvents=1 from detection', () => {
    const v = score({ behavioral: { totalPoints: 0, trajectoryLength: 0, approachPoints: 0, touchEvents: 1, keyEvents: 0 } });
    expect(hasCategory(v, 'vision_ai')).toBe(true);
    expect(hasCategory(v, 'behavioral')).toBe(true);
  });

  it('exempts touchEvents=3 (legitimate touch user)', () => {
    const v = score(
      { behavioral: { totalPoints: 0, trajectoryLength: 0, approachPoints: 0, touchEvents: 3, keyEvents: 0, interactionDuration: 1500 } },
      { ua: UA_IPHONE },
    );
    expect(hasCategory(v, 'vision_ai')).toBe(false);
    expect(hasCategory(v, 'behavioral')).toBe(false);
  });

  it('exempts keyEvents=2 with no mouse (Tab + Enter)', () => {
    const v = score({
      behavioral: { totalPoints: 0, trajectoryLength: 0, approachPoints: 0, touchEvents: 0, keyEvents: 2, interactionDuration: 1500 },
    });
    expect(hasCategory(v, 'vision_ai')).toBe(false);
  });
});

describe('mobile touch authenticity', () => {
  it('flags synthetic force=1 touches on mobile UA', () => {
    const v = score(
      {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0, keyEvents: 0,
          touchEvents: 10, touchTotalPoints: 10,
          touchForceMin: 1, touchForceMax: 1, touchForceVariance: 0, touchForceAllOne: true,
          touchRadiusMin: 0, touchRadiusMax: 0, touchRadiusVariance: 0,
          touchUniqueIdentifiers: 1, interactionDuration: 1500,
        },
      },
      { ua: UA_IPHONE },
    );
    expect(hasReasonIncluding(v, 'synthetic')).toBe(true);
  });

  it('does not run touch detectors on desktop UA', () => {
    const v = score(
      {
        behavioral: {
          touchEvents: 10, touchTotalPoints: 10, touchForceAllOne: true,
          touchForceMax: 1, touchForceVariance: 0,
        },
      },
      { ua: UA_CHROME_WIN },
    );
    expect(hasReasonIncluding(v, 'synthetic touch')).toBe(false);
    expect(hasReasonIncluding(v, 'force=1.0')).toBe(false);
  });
});

describe('JA3 fingerprint matching', () => {
  it('flags a known bot JA3 hash', () => {
    const v = score({}, { ja3Hash: '473cd7cb9faa642487833865d516e578' }); // curl
    expect(hasReasonIncluding(v, 'TLS fingerprint matches')).toBe(true);
  });
});

describe('JA4 from trusted headers', () => {
  // The documented behaviour of `trustedJA4Headers` is that it does not change
  // the score, because the built-in JA4 table is empty. If JA4 data is ever
  // added, this fails so the option's documentation is updated with it.
  it('reads the header but does not change the score', () => {
    const engine = new DetectionEngine();
    const base: DetectionContext = {
      ip: '73.15.22.100',
      siteKey: 'test',
      userAgent: UA_CHROME_WIN,
      headers: { 'user-agent': UA_CHROME_WIN, ...GOOD_HEADERS, 'x-ja4': 't13d1516h2_8daaf6152771_02713d6af862' },
    };
    const without = engine.score({}, base);
    const withJA4 = engine.score({}, { ...base, trustedJA4Headers: ['x-ja4'] });
    expect(withJA4.score).toBe(without.score);
    expect(hasReasonIncluding(withJA4, 'JA4')).toBe(false);
  });
});
