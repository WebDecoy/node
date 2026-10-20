/**
 * The clearance gate, for middleware that runs in front of the page.
 *
 * The same decision the Cloudflare, AWS and Netlify validators make, from the
 * same source: `gate.generated.js` is built from WebDecoy's validator code and
 * is never edited here. This file is the part an adapter needs around it, the
 * site's identity from the environment and one client-IP answer.
 *
 * What it does with a request, in order:
 *
 *  1. Credentials, verified crawlers (forward-confirmed reverse DNS) and
 *     validly signed agents pass before any token is asked for.
 *  2. A page no protected path covers passes.
 *  3. On a protected path, a valid `wd_clearance` cookie passes. A missing,
 *     invalid or revoked one is labelled; in monitor mode the request still
 *     passes, in enforce mode it gets the challenge: a real browser earns the
 *     cookie and is sent back, a client that runs no JavaScript stays there.
 *
 * Which paths are protected, and whether the site monitors or enforces, is
 * set in WebDecoy, not here. Every failure, WebDecoy unreachable included,
 * lets the request through.
 */

import { runGate, cleanHeaders, DEFAULT_INGEST, VERCEL_VALIDATOR_CAPABILITIES, BUILD } from './gate.generated';
import type { GateEnv, GateOutcome } from './gate.generated';
import { resolveClientIp } from '../client-ip';
import type { TrustedProxies } from '../client-ip';

export type { GateEnv, GateOutcome } from './gate.generated';
export { cleanHeaders, DEFAULT_INGEST, VERCEL_VALIDATOR_CAPABILITIES, BUILD as CLEARANCE_GATE_BUILD };

export interface ClearanceGateOptions {
  /** WEBDECOY_SITE_KEY by default. */
  siteKey?: string;
  /** WEBDECOY_SCANNER_ID by default. */
  scannerId?: string;
  /** WEBDECOY_SENSOR_KEY by default. A secret: set it in the platform's environment, never in code. */
  sensorKey?: string;
  /** WEBDECOY_INGEST, else WebDecoy's ingest. */
  ingest?: string;
  /**
   * How many proxies sit in front of the middleware. Defaults to `1`, the
   * hosting platform, which is right on Vercel. See resolveClientIp.
   */
  trustProxy?: TrustedProxies;
}

/** What a platform passes with each request. */
export interface ClearanceContext {
  waitUntil?: (promise: Promise<unknown>) => void;
}

function fromEnv(name: string): string {
  try {
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
    return (env?.[name] ?? '').trim();
  } catch {
    return '';
  }
}

/** The site's identity, from options first and the environment second; null when incomplete. */
export function resolveGateEnv(options: ClearanceGateOptions = {}): GateEnv | null {
  const siteKey = (options.siteKey ?? fromEnv('WEBDECOY_SITE_KEY')).trim();
  const scannerId = (options.scannerId ?? fromEnv('WEBDECOY_SCANNER_ID')).trim();
  const sensorKey = (options.sensorKey ?? fromEnv('WEBDECOY_SENSOR_KEY')).trim();
  if (!siteKey || !scannerId || !sensorKey) return null;
  const ingest = (options.ingest ?? fromEnv('WEBDECOY_INGEST')).trim() || DEFAULT_INGEST;
  return { siteKey, scannerId, sensorKey, ingest };
}

let warnedMissing = false;

/**
 * A gate bound to one site: call it with each request.
 *
 * Missing configuration turns it into a pass-through that says so once,
 * rather than an unproven gate: a site that forgot its sensor key must keep
 * serving pages.
 */
export function createClearanceGate(
  options: ClearanceGateOptions = {}
): (request: Request, context?: ClearanceContext) => Promise<GateOutcome> {
  const trustProxy = options.trustProxy ?? 1;
  return async (request, context = {}) => {
    const env = resolveGateEnv(options);
    if (!env) {
      if (!warnedMissing) {
        warnedMissing = true;
        console.warn(
          '[WebDecoy] clearance gate is off: set WEBDECOY_SITE_KEY, WEBDECOY_SCANNER_ID and WEBDECOY_SENSOR_KEY.'
        );
      }
      return { action: 'continue', headers: cleanHeaders(request), verdict: null };
    }
    const ip = resolveClientIp({ headers: request.headers, trustProxy }) ?? '';
    return runGate(request, { ip, waitUntil: context.waitUntil }, env);
  };
}
