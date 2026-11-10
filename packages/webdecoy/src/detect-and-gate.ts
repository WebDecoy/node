/**
 * Detection and the clearance gate, in one middleware.
 *
 * A site on Vercel has one middleware file. Detection (what is this client,
 * report it) and the clearance gate (does this protected page need a token)
 * used to be two separate middlewares with two sets of credentials, so a site
 * had to pick one or hand-write a chain. This runs both, for one request, and
 * returns one outcome:
 *
 *  - Detection runs when an API key is configured (`apiKey`, else
 *    `WEBDECOY_API_KEY`). It reports the reserved test trigger
 *    (`curl -A "WebDecoy-Test/1.0"`), tripwire hits and clients that look like
 *    bots, including every agent the bot registry names.
 *  - The gate runs when the site's identity is configured (`siteKey`,
 *    `scannerId`, `sensorKey`, else the WEBDECOY_* variables), exactly as
 *    `createClearanceGate()` does on its own.
 *
 * Without an API key this is the gate alone, unchanged. Without either, every
 * request passes. Nothing here throws: a failure in detection or the gate lets
 * the request through.
 *
 * Both halves resolve the client IP the same way and see the same path, so a
 * request the gate refuses (or would refuse, in monitor mode) and the
 * detection reported for it describe the same client.
 */

import { createClearanceGate, cleanHeaders, fromEnv } from './clearance';
import type { ClearanceGateOptions, ClearanceContext, GateOutcome } from './clearance';
import { createFetchGuard } from './fetch-guard';
import type { FetchGuard, FetchGuardOptions } from './fetch-guard';
import { shouldSkipPath } from './adapter-core';
import type { Decision } from './decision';

/** Request headers that carry the detection verdict to the application. */
const DECISION_HEADER = 'x-webdecoy-decision';
const DETECTION_ID_HEADER = 'x-webdecoy-detection-id';
const WOULD_BLOCK_HEADER = 'x-webdecoy-would-block';

export interface DetectAndGateOptions
  extends ClearanceGateOptions,
    Omit<FetchGuardOptions, 'getIP' | 'honeytoken' | 'trustProxy'> {
  /**
   * The WebDecoy API key. `WEBDECOY_API_KEY` by default. A secret: set it in the
   * platform's environment, never in code. Without one, no detection runs and
   * this is the clearance gate alone.
   */
  apiKey?: string;

  /**
   * What a blocking detection verdict does. Defaults to `'monitor'`: the
   * request is served and the verdict rides on the request headers
   * (`x-webdecoy-decision`, `x-webdecoy-detection-id`, `x-webdecoy-would-block`).
   * `'enforce'` answers a blocked request with 403 (or 429 for a rate limit).
   *
   * This is detection's mode only. Whether the clearance gate monitors or
   * enforces is set per site in WebDecoy.
   */
  mode?: 'monitor' | 'enforce';
}

/** Detection's verdict on a request, when detection ran. */
export interface DetectAndGateOutcome {
  /** What to do with the request. Same shape as the gate's outcome. */
  outcome: GateOutcome;
  /** The detection decision, or null when detection did not run or failed. */
  decision: Decision | null;
}

let warnedBadKey = false;

/**
 * Detection then the clearance gate, bound to one site: call it with each
 * request. Options default to the environment.
 */
export function createDetectAndGate(
  options: DetectAndGateOptions = {}
): (request: Request, context?: ClearanceContext) => Promise<DetectAndGateOutcome> {
  const gate = createClearanceGate(options);
  const trustProxy = options.trustProxy ?? 1;

  // Built on the first request that has a key, and rebuilt only if the key
  // changes, so an install that sets the variable later starts reporting
  // without a redeploy of this code.
  let guard: FetchGuard | null = null;
  let guardKey = '';
  let failedKey = '';

  function guardFor(apiKey: string): FetchGuard | null {
    if (guard && guardKey === apiKey) return guard;
    if (failedKey === apiKey) return null;
    try {
      guard = createFetchGuard({ ...options, apiKey, trustProxy, honeytoken: false, mode: options.mode ?? 'monitor' });
      guardKey = apiKey;
      return guard;
    } catch (error) {
      // A malformed key is a configuration mistake, not a reason to stop
      // serving pages. Say so once and run the gate alone.
      failedKey = apiKey;
      if (!warnedBadKey) {
        warnedBadKey = true;
        console.warn(
          `[WebDecoy] detection is off: ${error instanceof Error ? error.message : 'the API key was rejected'}`
        );
      }
      return null;
    }
  }

  async function detect(request: Request, apiKey: string) {
    try {
      const g = guardFor(apiKey);
      if (!g) return null;
      if (shouldSkipPath(new URL(request.url).pathname, options.skipPaths)) return null;
      return await g.check(request);
    } catch {
      return null; // fail open
    }
  }

  async function runGate(request: Request, context?: ClearanceContext): Promise<GateOutcome> {
    try {
      return await gate(request, context);
    } catch {
      return { action: 'continue', headers: null, verdict: null };
    }
  }

  return async (request, context) => {
    const apiKey = (options.apiKey ?? fromEnv('WEBDECOY_API_KEY')).trim();
    if (!apiKey) return { outcome: await runGate(request, context), decision: null };

    // Concurrently: neither depends on the other, and the request waits on both.
    const [guarded, gated] = await Promise.all([detect(request, apiKey), runGate(request, context)]);
    if (!guarded) return { outcome: gated, decision: null };

    const { decision, response } = guarded;
    // Detection first: an enforced detection block answers before the gate's.
    if (response) return { outcome: { action: 'respond', response }, decision };
    if (gated.action === 'respond') return { outcome: gated, decision };

    try {
      const headers = gated.headers ? new Headers(gated.headers) : cleanHeaders(request);
      // Inbound copies go first: the application must not be told a verdict
      // by the client being judged.
      headers.delete(DECISION_HEADER);
      headers.delete(DETECTION_ID_HEADER);
      headers.delete(WOULD_BLOCK_HEADER);
      headers.set(DECISION_HEADER, decision.detection?.decision ?? '');
      headers.set(DETECTION_ID_HEADER, decision.detection?.detection_id ?? '');
      headers.set(WOULD_BLOCK_HEADER, String(!decision.allowed));
      return { outcome: { action: 'continue', headers, verdict: gated.verdict }, decision };
    } catch {
      return { outcome: gated, decision };
    }
  };
}
