/**
 * wd_clearance minting (WAF Enforcement PRD FR6 / closes the #124 loop).
 *
 * Real browsers earn a signed clearance token from WebDecoy's ingest service and
 * carry it in a first-party cookie. The edge validator (FR7) lets tokened
 * sessions through; a decoy hit denies the token's fp (deny-at-mint + live-token
 * revocation). This is the *allow-and-observe* path — it mints silently during
 * normal browsing so the loop covers monitor mode, not just the enforce-mode
 * challenge interstitial.
 *
 * PERFORMANCE: the mint is deferred to idle, runs at most once per session (skips
 * when a fresh cookie already exists), and never solves a proof-of-work. The only
 * device-tier work — one canvas + one WebGL read — is done by the collector, once.
 * computeDeviceFP itself does NO canvas/WebGL: it consumes the collector's output.
 */

import { sha256 } from './sha256';
import { EnvironmentalCollector } from './collectors/environment';

export const CLEARANCE_COOKIE = 'wd_clearance';

/**
 * Canonical device-fp algorithm version. The fp is the deny-list key, so this
 * string is a CONTRACT: it MUST stay byte-identical to the edge challenge page
 * (app repo: edge/clearance-worker challengePage()). If normal-mode minting and
 * the challenge page computed different fps for the same browser, a decoy-
 * triggered deny would catch one token but not the other — the lockout would
 * leak. Bump the version prefix (never edit in place) to evolve the algorithm.
 */
export const FP_VERSION = 'wdfp1';

/** Default WebDecoy ingest origin (issuance endpoint host). */
export const DEFAULT_INGEST_URL = 'https://ingest.webdecoy.com';

export interface DeviceFPInputs {
  /** Collector _getCanvasHash() output — { hash, supported } or { supported:false }. */
  canvasHash: Record<string, unknown> | null;
  /** Collector _getWebGLInfo() output — { renderer, vendor, supported } or { supported:false }. */
  webglInfo: Record<string, unknown> | null;
}

/**
 * Stable device fingerprint the clearance token binds to. PURE: the caller passes
 * the collector's already-computed canvas/WebGL signals; this function performs no
 * canvas/WebGL work of its own (only cheap synchronous property reads). Uses the
 * stable device subset — canvas, WebGL, screen, timezone, platform, language — and
 * deliberately excludes User-Agent (churns on browser auto-update) and any
 * behavioral/session signal (would change per load).
 */
export async function computeDeviceFP(env: DeviceFPInputs): Promise<string> {
  const ch = env.canvasHash;
  const canvas = ch && ch.supported ? String(ch.hash) : 'na';

  const wg = env.webglInfo;
  const webgl = wg && wg.supported ? String(wg.renderer) + '~' + String(wg.vendor) : 'na';

  const scr = `${screen.width}x${screen.height}x${screen.colorDepth}`;

  let tz = 'na';
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'na';
  } catch {
    /* ignore */
  }

  const plat = navigator.platform || 'na';
  const lang = navigator.language || 'na';

  return sha256([FP_VERSION, canvas, webgl, scr, tz, plat, lang].join('|'));
}

interface MintResponse {
  granted?: boolean;
  token?: string;
  expires_in?: number;
}

/** Call the public issuance endpoint. Returns null on any failure (fail open). */
async function mint(
  ingestUrl: string,
  siteKey: string,
  fp: string,
  scope: string,
): Promise<{ token: string; expiresIn: number } | null> {
  try {
    const res = await fetch(ingestUrl.replace(/\/$/, '') + '/api/v1/clearance', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        aid: siteKey,
        fp,
        scope,
        ua: navigator.userAgent,
        webdriver: (navigator as unknown as { webdriver?: boolean }).webdriver === true,
        headless: /HeadlessChrome/.test(navigator.userAgent),
      }),
    });
    const out = (await res.json()) as MintResponse;
    if (out.granted && out.token) {
      return { token: out.token, expiresIn: out.expires_in || 1800 };
    }
  } catch {
    /* fail open */
  }
  return null;
}

function readCookie(name: string): string | null {
  for (const part of document.cookie.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim() || null;
  }
  return null;
}

function setClearanceCookie(token: string, maxAgeSec: number): void {
  // Attributes MUST match the edge challenge page so both mint paths interoperate.
  document.cookie =
    `${CLEARANCE_COOKIE}=${token}; path=/; secure; samesite=lax; max-age=${maxAgeSec}`;
}

/** Defer work to browser idle time, with a timeout fallback. */
function whenIdle(fn: () => void): void {
  const ric = (window as unknown as { requestIdleCallback?: (cb: () => void) => void })
    .requestIdleCallback;
  if (typeof ric === 'function') {
    ric(fn);
  } else {
    setTimeout(fn, 1200);
  }
}

export interface ClearanceOptions {
  siteKey: string;
  /** WebDecoy ingest origin. Defaults to DEFAULT_INGEST_URL. */
  ingestUrl?: string;
  /** Route-group scope; '' = tenant-wide (default), valid on every route. */
  scope?: string;
}

/**
 * Start silent clearance minting. Idempotent guard, deferred to idle, at most once
 * per session: if a fresh cookie already exists it only schedules a refresh; only
 * an absent/near-expiry cookie triggers a collect + mint. Never blocks paint or
 * interaction; failures are swallowed (the edge validator fails open regardless).
 */
export function startClearance(opts: ClearanceOptions): void {
  if (!opts.siteKey || typeof document === 'undefined') return;
  const ingestUrl = opts.ingestUrl || DEFAULT_INGEST_URL;
  const scope = opts.scope || '';

  const run = async (): Promise<void> => {
    if (readCookie(CLEARANCE_COOKIE)) {
      // Already cleared this session; re-check periodically to refresh near expiry.
      return;
    }
    const env = new EnvironmentalCollector();
    const fp = await computeDeviceFP({
      canvasHash: env._getCanvasHash(),
      webglInfo: env._getWebGLInfo(),
    });
    const minted = await mint(ingestUrl, opts.siteKey, fp, scope);
    if (minted) {
      setClearanceCookie(minted.token, minted.expiresIn);
      // Re-mint a little before expiry so a real browser stays continuously cleared.
      const refreshMs = Math.max(60_000, (minted.expiresIn - 120) * 1000);
      setTimeout(() => startClearance(opts), refreshMs);
    }
  };

  whenIdle(() => {
    void run();
  });
}
