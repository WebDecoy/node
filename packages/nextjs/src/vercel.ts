/**
 * WebDecoy for Next.js on Vercel: detection and the clearance gate in one
 * middleware, configured from the environment.
 *
 * @example
 * ```typescript
 * // middleware.ts (Next.js 13-15), or proxy.ts (Next.js 16)
 * import webdecoy from '@webdecoy/nextjs/vercel';
 *
 * export default webdecoy;
 *
 * export const config = {
 *   // Everything but static assets. Keep /.well-known: the challenge uses it.
 *   matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
 * };
 * ```
 *
 * Import then export, rather than `export { default } from ...`: Next.js 16
 * looks for the default export without following a re-export and fails the
 * build on that one-line form, in `proxy.ts` and `middleware.ts` alike. And
 * `config` has to be written in the file itself, because Next reads it
 * statically.
 *
 * Environment:
 *
 *  - `WEBDECOY_API_KEY` turns on detection: bots are reported to WebDecoy,
 *    including the reserved test trigger (`curl -A "WebDecoy-Test/1.0" ...`),
 *    and the verdict reaches the app as request headers
 *    (`x-webdecoy-decision`, `x-webdecoy-detection-id`, `x-webdecoy-would-block`).
 *  - `WEBDECOY_SITE_KEY`, `WEBDECOY_SCANNER_ID` and `WEBDECOY_SENSOR_KEY` turn
 *    on the clearance gate for the paths the site protects in WebDecoy; the
 *    page receives its verdict as `x-wd-clearance` (see `getEdgeVerdict()`).
 *
 * Either half works without the other; with neither, every request passes.
 * Detection starts in monitor mode and the gate follows the site's mode in
 * WebDecoy (monitor by default), so installing this changes no response until
 * you choose to enforce. Every failure lets the request through.
 *
 * To customize, use {@link createVercelMiddleware}:
 *
 * ```typescript
 * // middleware.ts
 * import { createVercelMiddleware } from '@webdecoy/nextjs/vercel';
 * import { tripwire } from '@webdecoy/node';
 *
 * export default createVercelMiddleware({
 *   rules: [tripwire({ paths: ['/admin-backup.zip'] })],
 * });
 *
 * export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
 * ```
 */

import { NextResponse } from 'next/server';
import type { NextRequest, NextFetchEvent } from 'next/server';
import { createDetectAndGate } from '@webdecoy/node';
import type { DetectAndGateOptions } from '@webdecoy/node';

export type { DetectAndGateOptions } from '@webdecoy/node';

/**
 * Detection and the clearance gate as Next.js middleware. Options default to
 * the environment (`WEBDECOY_API_KEY`, `WEBDECOY_SITE_KEY`,
 * `WEBDECOY_SCANNER_ID`, `WEBDECOY_SENSOR_KEY`).
 */
export function createVercelMiddleware(
  options: DetectAndGateOptions = {}
): (req: NextRequest, event?: NextFetchEvent) => Promise<Response> {
  const decide = createDetectAndGate(options);
  return async (req, event) => {
    try {
      const { outcome } = await decide(req, {
        waitUntil: event ? (p) => event.waitUntil(p) : undefined,
      });
      if (outcome.action === 'respond') return outcome.response;
      if (!outcome.headers) return NextResponse.next();
      return NextResponse.next({ request: { headers: outcome.headers } });
    } catch {
      return NextResponse.next(); // fail open
    }
  };
}

/** The middleware configured from WEBDECOY_* environment variables. */
const middleware = createVercelMiddleware();
export default middleware;
