/**
 * WebDecoy clearance for Vercel Routing Middleware, any framework.
 *
 * Astro, SvelteKit, Nuxt, Remix or a static site on Vercel: put this in
 * `middleware.ts` at the project root and set WEBDECOY_SITE_KEY,
 * WEBDECOY_SCANNER_ID and WEBDECOY_SENSOR_KEY in the project's environment.
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
 * Next.js sites use `withClearance()` from @webdecoy/nextjs instead.
 *
 * Starts in whatever mode the site has in WebDecoy, monitor by default, and
 * enforces only once it is switched there and paths are protected.
 */

import { createClearanceGate } from './clearance';
import type { ClearanceGateOptions, ClearanceContext } from './clearance';
import type { GateOutcome } from './clearance';

export type { ClearanceGateOptions, ClearanceContext } from './clearance';

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

/** Routing Middleware bound to one site. Options default to the environment. */
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

/** The middleware configured from WEBDECOY_* environment variables. */
const middleware = clearanceMiddleware();
export default middleware;
