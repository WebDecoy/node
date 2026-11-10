/**
 * WebDecoy for Vercel Routing Middleware, any framework.
 *
 * Astro, SvelteKit, Nuxt, Remix or a static site on Vercel: put this in
 * `middleware.ts` at the project root.
 *
 * ```ts
 * // middleware.ts
 * export { default } from '@webdecoy/node/vercel';
 *
 * export const config = {
 *   // Everything but static assets. Keep /.well-known: the challenge uses it.
 *   matcher: ['/((?!_astro/|_next/static/|favicon.ico|.*\\.(?:css|js|png|jpg|svg|webp|woff2?)$).*)'],
 * };
 * ```
 *
 * It reads the project's environment:
 *
 *  - `WEBDECOY_API_KEY` turns on detection: the request is classified and bots
 *    are reported to WebDecoy, including the reserved test trigger
 *    (`curl -A "WebDecoy-Test/1.0" https://your-site/`).
 *  - `WEBDECOY_SITE_KEY`, `WEBDECOY_SCANNER_ID` and `WEBDECOY_SENSOR_KEY` turn on
 *    the clearance gate for the paths the site protects in WebDecoy.
 *
 * Either half works without the other, and with neither every request passes.
 * Detection starts in monitor mode and the gate in whatever mode the site has
 * in WebDecoy (monitor by default), so installing this changes no response
 * until you choose to enforce. Every failure lets the request through.
 *
 * Next.js sites use `@webdecoy/nextjs/vercel`, the same middleware in Next's
 * types.
 */

import { createClearanceGate } from './clearance';
import type { ClearanceGateOptions, ClearanceContext } from './clearance';
import type { GateOutcome } from './clearance';
import { createDetectAndGate } from './detect-and-gate';
import type { DetectAndGateOptions } from './detect-and-gate';

export type { ClearanceGateOptions, ClearanceContext } from './clearance';
export type { DetectAndGateOptions } from './detect-and-gate';

/**
 * Turn the gate's answer into what Vercel middleware returns.
 *
 * Continuing with changed request headers is a response carrying
 * instructions: `x-middleware-next` and the full replacement header set
 * under `x-middleware-request-*`, listed in `x-middleware-override-headers`.
 * That is what `next({ request: { headers } })` from @vercel/functions
 * sends; spelled out here so the SDK needs no Vercel package. Returning
 * nothing continues the request untouched.
 */
export function toMiddlewareResponse(outcome: GateOutcome): Response | undefined {
  if (outcome.action === 'respond') return outcome.response;
  if (!outcome.headers) return undefined;
  const instructions = new Headers({ 'x-middleware-next': '1' });
  const names: string[] = [];
  outcome.headers.forEach((value, name) => {
    instructions.set(`x-middleware-request-${name}`, value);
    names.push(name);
  });
  instructions.set('x-middleware-override-headers', names.join(','));
  return new Response(null, { headers: instructions });
}

/**
 * The clearance gate alone, as Routing Middleware. Options default to the
 * environment. Reports no detections; {@link createVercelMiddleware} does both.
 */
export function clearanceMiddleware(
  options: ClearanceGateOptions = {}
): (request: Request, context?: ClearanceContext) => Promise<Response | undefined> {
  const gate = createClearanceGate(options);
  return async (request, context) => {
    try {
      return toMiddlewareResponse(await gate(request, context));
    } catch {
      return undefined; // fail open
    }
  };
}

/**
 * Detection and the clearance gate as Routing Middleware, for customizing
 * what the default export does. Options default to the environment.
 *
 * ```ts
 * // middleware.ts
 * import { createVercelMiddleware } from '@webdecoy/node/vercel';
 * import { tripwire } from '@webdecoy/node';
 *
 * export default createVercelMiddleware({
 *   rules: [tripwire({ paths: ['/admin-backup.zip'] })],
 * });
 *
 * export const config = { matcher: ['/((?!_astro/|favicon.ico).*)'] };
 * ```
 *
 * Without an API key it is exactly {@link clearanceMiddleware}.
 */
export function createVercelMiddleware(
  options: DetectAndGateOptions = {}
): (request: Request, context?: ClearanceContext) => Promise<Response | undefined> {
  const decide = createDetectAndGate(options);
  return async (request, context) => {
    try {
      return toMiddlewareResponse((await decide(request, context)).outcome);
    } catch {
      return undefined; // fail open
    }
  };
}

/** The middleware configured from WEBDECOY_* environment variables. */
const middleware = createVercelMiddleware();
export default middleware;
