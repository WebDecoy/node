/**
 * wd_clearance minting.
 *
 * Real browsers earn a signed clearance token from WebDecoy's ingest service and
 * carry it in a first-party cookie. The edge validator lets tokened
 * sessions through; a decoy hit denies the token's fp (deny-at-mint + live-token
 * revocation). This is the *allow-and-observe* path — it mints silently during
 * normal browsing so the loop covers monitor mode, not just the enforce-mode
 * challenge interstitial.
 *
 * PERFORMANCE: the initial mint is deferred to idle, fresh cookies are reused,
 * renewal is bounded, and minting never solves a proof-of-work. The only
 * device-tier work — one canvas + one WebGL read — is done by the collector, once.
 * computeDeviceFP itself does NO canvas/WebGL: it consumes the collector's output.
 */

import { sha256 } from './sha256';
import { EnvironmentalCollector } from './collectors/environment';
import { watchInteraction, type BehaviorAggregate } from './clearance-behavior';

export const CLEARANCE_COOKIE = 'wd_clearance';

/**
 * Canonical device-fp algorithm version. This fp is the ENFORCEMENT identity —
 * the clearance token binds to it and the deny-list keys on it — so the string
 * is a CONTRACT. Three implementations must agree byte-for-byte:
 *
 *   1. this function
 *   2. app repo `edge/clearance-worker/src/device-fp.ts` (the interstitial)
 *   3. app repo `cdn/public/bot-detection-pro.js` computeClearanceFP()
 *
 * If two of them computed different fps for the same browser, a decoy-triggered
 * deny would catch one and not the other — the lockout would leak, silently.
 * All three are pinned to the same golden vector (see clearance.test.ts here,
 * and the device-fp tests in the app repo).
 *
 * Do NOT confuse this with the `device_fp` the scoring pipeline composes
 * server-side: that is a correlation key that works without any token, this is
 * what a deny actually locks out. They are different identity spaces.
 *
 * Bump the version prefix (never edit in place) to evolve the algorithm.
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

type MintResult = { token: string; expiresIn: number } | { denied: true } | null;
const REFRESH_MARGIN_MS = 120_000;
const COOKIE_CHECK_MS = 60_000;
const MAX_TOKEN_AGE_MS = 1_800_000;
const MINT_TIMEOUT_MS = 10_000;

/** Call the public issuance endpoint. Returns null on any failure (fail open).
 *  `behavior`, when present, carries the session's interaction aggregates and
 *  can earn the token a graded 'human-likely' trust level. */
async function mint(
  ingestUrl: string,
  siteKey: string,
  fp: string,
  scope: string,
  behavior?: BehaviorAggregate,
): Promise<MintResult> {
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), MINT_TIMEOUT_MS);
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
        ...(behavior ? { behavior } : {}),
      }),
      signal: abort.signal,
    });
    if (!res.ok) return null;
    const out = (await res.json()) as MintResponse;
    if (out.granted && out.token) {
      const ttl = out.expires_in;
      return { token: out.token, expiresIn: typeof ttl === 'number' && Number.isFinite(ttl) && ttl > 0 ? Math.min(ttl, 1800) : 1800 };
    }
    if (out.granted === false) return { denied: true };
  } catch {
    /* fail open */
  } finally { clearTimeout(timeout); }
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
  const ric = (window as unknown as { requestIdleCallback?: (cb: () => void, options?: { timeout: number }) => void })
    .requestIdleCallback;
  if (typeof ric === 'function') {
    ric.call(window, fn, { timeout: 1200 });
  } else {
    setTimeout(fn, 1200);
  }
}

export interface ClearanceOptions {
  siteKey: string;
  /** WebDecoy ingest origin. Defaults to DEFAULT_INGEST_URL. */
  ingestUrl?: string;
  /**
   * Reserved. Sent with the mint request, but no validator restricts a token by
   * it. A clearance token is bound to the organization: any of its sites accepts
   * it, subject to expiry, the fingerprint deny list and the verification level
   * required by the path it is used on. Use a path's verification level to ask
   * for stronger proof on sensitive routes.
   */
  scope?: string;
  /**
   * Collect interaction aggregates and upgrade the token to a graded
   * 'human-likely' trust level once the visitor actually interacts.
   * Default true. Set false to mint clean tokens only — routes that require a
   * minimum trust level will then always challenge.
   *
   * See clearance-behavior.ts for exactly what is collected; it is aggregate
   * counts and variances, never coordinates, keys or content.
   */
  behavior?: boolean;
}

/** One behavioral upgrade per page load; repeated startup must not add listeners. */
let upgradeStarted = false;

interface ClearanceSession {
  key: string;
  opts: ClearanceOptions;
  token: string | null;
  expiresAt: number;
  renewAt: number;
  retryAt: number;
  timer?: ReturnType<typeof setTimeout>;
  running: boolean;
  stopped: boolean;
  failures: number;
  fingerprint?: Promise<string>;
  behavior?: BehaviorAggregate;
  lastBehavior?: BehaviorAggregate;
  wake: () => void;
}
let session: ClearanceSession | undefined;

// The unsigned payload is ONLY a scheduling hint. Server and edge verification
// remain authoritative. Remember the bound on first seeing a token, so a bogus
// distant expiry cannot postpone renewal forever.
function expiryHint(token: string): number {
  try {
    const encoded = token.split('.')[0];
    if (encoded.length > 8192) return Date.now() + COOKIE_CHECK_MS + REFRESH_MARGIN_MS;
    const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const exp = JSON.parse(atob(base64)).exp;
    if (typeof exp === 'number' && Number.isFinite(exp) && exp > 0) {
      return Math.min(exp * 1000, Date.now() + MAX_TOKEN_AGE_MS);
    }
  } catch { /* old or malformed cookies get one bounded grace period */ }
  return Date.now() + COOKIE_CHECK_MS + REFRESH_MARGIN_MS;
}

function schedule(s: ClearanceSession, delay: number): void {
  if (s.timer !== undefined) clearTimeout(s.timer);
  if (s !== session || s.stopped) return;
  s.timer = setTimeout(() => { s.timer = undefined; void maintain(s); }, Math.max(1000, delay));
}

async function maintain(s: ClearanceSession): Promise<void> {
  if (s !== session || s.stopped || s.running) return;
  const token = readCookie(CLEARANCE_COOKIE);
  if (token !== s.token) {
    s.token = token;
    s.expiresAt = token ? expiryHint(token) : 0;
    s.renewAt = s.expiresAt - Math.min(REFRESH_MARGIN_MS, Math.max(0, s.expiresAt - Date.now()) / 3);
  }
  if (s.retryAt > Date.now()) {
    schedule(s, s.retryAt - Date.now());
    return;
  }
  if (!s.behavior && token && s.renewAt > Date.now()) {
    schedule(s, Math.min(COOKIE_CHECK_MS, s.renewAt - Date.now()));
    return;
  }
  s.running = true;
  const behavior = s.behavior;
  s.behavior = undefined;
  try {
    if (!s.fingerprint) {
      s.fingerprint = (async () => {
        const env = new EnvironmentalCollector();
        return computeDeviceFP({ canvasHash: env._getCanvasHash(), webglInfo: env._getWebGLInfo() });
      })();
    }
    const fp = await s.fingerprint;
    const result = await mint(s.opts.ingestUrl || DEFAULT_INGEST_URL, s.opts.siteKey, fp, s.opts.scope || '', behavior || s.lastBehavior);
    if (s !== session) return; // an old in-flight request cannot replace a new site's cookie
    if (result && 'token' in result) {
      setClearanceCookie(result.token, result.expiresIn);
      s.token = readCookie(CLEARANCE_COOKIE);
      s.expiresAt = Date.now() + result.expiresIn * 1000;
      s.renewAt = s.expiresAt - Math.min(REFRESH_MARGIN_MS, result.expiresIn * 1000 / 3);
      s.failures = 0;
      if (behavior) s.lastBehavior = behavior;
      s.retryAt = 0;
      schedule(s, Math.min(COOKIE_CHECK_MS, s.renewAt - Date.now()));
    } else if (result && 'denied' in result) {
      // Refusal is not an outage. Do not repeatedly attempt to replace denied
      // clearance; the edge still decides what the existing cookie may access.
      s.stopped = true;
      if (s.timer !== undefined) clearTimeout(s.timer);
    } else {
      s.failures++;
      const delay = Math.min(300_000, COOKIE_CHECK_MS * Math.pow(2, Math.min(s.failures - 1, 3)));
      s.retryAt = Date.now() + delay;
      schedule(s, delay);
    }
  } catch {
    s.fingerprint = undefined;
    s.failures++;
    const delay = Math.min(300_000, COOKIE_CHECK_MS * Math.pow(2, Math.min(s.failures - 1, 3)));
    s.retryAt = Date.now() + delay;
    schedule(s, delay);
  } finally {
    s.running = false;
    if (s.behavior && !s.stopped && s === session) schedule(s, 1000);
  }
}

/**
 * Watch for real interaction and, once there is enough of it, re-mint the
 * session's token with the behavioral evidence attached.
 *
 * Upgrade only after real interaction, sharing the renewal request and cached
 * fingerprint. A failed upgrade leaves the existing cookie untouched.
 */
function startBehavioralUpgrade(s: ClearanceSession): void {
  if (upgradeStarted) return;
  upgradeStarted = true;

  watchInteraction((behavior) => {
    if (s !== session || s.stopped) return;
    s.behavior = behavior;
    void maintain(s);
  });
}

/**
 * Start one silent clearance lifecycle. Initial work is deferred to idle; fresh
 * cookies schedule renewal and only absent/near-expiry cookies trigger minting.
 * Transient failures back off; server refusals stop automatic attempts. The edge
 * remains authoritative, including when the browser cannot obtain clearance.
 */
export function startClearance(opts: ClearanceOptions): void {
  if (!opts.siteKey || typeof document === 'undefined') return;
  const ingestUrl = opts.ingestUrl || DEFAULT_INGEST_URL;
  const key = JSON.stringify([ingestUrl.replace(/\/$/, ''), opts.siteKey, opts.scope || '']);
  if (!session || session.key !== key) {
    if (session) {
      if (session.timer !== undefined) clearTimeout(session.timer);
      document.removeEventListener('visibilitychange', session.wake);
    }
    upgradeStarted = false;
    const s: ClearanceSession = {
      key, opts: { ...opts }, token: null, expiresAt: 0, renewAt: 0, retryAt: 0, running: false, stopped: false, failures: 0,
      wake: () => { if (document.visibilityState === 'visible') void maintain(s); },
    };
    session = s;
    document.addEventListener('visibilitychange', s.wake);
    whenIdle(() => { void maintain(s); });
  }

  // Independent of the mint above: a session that already holds a token can
  // still upgrade it once the visitor interacts, and one that mints a fresh
  // clean token upgrades that. Never blocks, never fires without interaction.
  if (opts.behavior !== false) {
    startBehavioralUpgrade(session);
  }
}

/** Reset the once-per-page-load upgrade guard. Test-only. */
export function _resetBehavioralUpgradeForTests(): void {
  upgradeStarted = false;
}

/** Reset the renewal lifecycle. Test-only. */
export function _resetClearanceForTests(): void {
  if (session) {
    if (session.timer !== undefined) clearTimeout(session.timer);
    document.removeEventListener('visibilitychange', session.wake);
  }
  session = undefined;
  upgradeStarted = false;
}
