/**
 * WebDecoy clearance in Next.js middleware.
 *
 * The clearance gate from @webdecoy/node, the same decision WebDecoy's
 * Cloudflare, AWS and Netlify validators make, run on Vercel (or any host
 * running Next.js middleware) with no proxy in front. Which paths need a
 * token, and whether the site monitors or enforces, is set in WebDecoy.
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { withClearance } from '@webdecoy/nextjs';
 *
 * // Reads WEBDECOY_SITE_KEY, WEBDECOY_SCANNER_ID and WEBDECOY_SENSOR_KEY.
 * export default withClearance();
 *
 * export const config = {
 *   // Everything but static assets. Keep /.well-known: the challenge uses it.
 *   matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
 * };
 * ```
 *
 * A page the gate lets through receives the verdict as `x-wd-clearance`;
 * `getEdgeVerdict()` reads it in a route handler or server component.
 */

import { NextResponse } from 'next/server';
import type { NextRequest, NextFetchEvent } from 'next/server';
import { createClearanceGate } from '@webdecoy/node';
import type { ClearanceGateOptions } from '@webdecoy/node';

export type { ClearanceGateOptions } from '@webdecoy/node';

/** Next.js middleware that runs the clearance gate. Options default to the environment. */
export function withClearance(
  options: ClearanceGateOptions = {}
): (req: NextRequest, event?: NextFetchEvent) => Promise<Response> {
  const gate = createClearanceGate(options);
  return async (req, event) => {
    try {
      const outcome = await gate(req, { waitUntil: event ? (p) => event.waitUntil(p) : undefined });
      if (outcome.action === 'respond') return outcome.response;
      if (!outcome.headers) return NextResponse.next();
      return NextResponse.next({ request: { headers: outcome.headers } });
    } catch {
      return NextResponse.next(); // fail open
    }
  };
}
