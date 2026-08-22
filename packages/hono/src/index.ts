/**
 * Web Decoy middleware for Hono.
 *
 * Hono is the default on Cloudflare Workers, Bun and Deno — the runtimes where
 * the rest of our stack already sits. The Cloudflare edge sensor fronts these
 * deployments and tags every request it forwards, and `readEdgeVerdict()` exists
 * so the origin can act on that tag. Until now there was no origin middleware
 * there to do it.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { webdecoy } from '@webdecoy/hono';
 * import { tripwire, rateLimit } from '@webdecoy/node';
 *
 * const app = new Hono();
 *
 * app.use('*', webdecoy({
 *   rules: [tripwire(), rateLimit({ max: 100, window: 60 })],
 *   skipPaths: ['/health'],
 * }));
 * ```
 */

import type { Context, MiddlewareHandler, Next } from 'hono';
import { createFetchGuard } from '@webdecoy/node';
import type { FetchGuardOptions, Decision } from '@webdecoy/node';

export interface WebDecoyHonoOptions extends Omit<FetchGuardOptions, 'onBlocked'> {
  /**
   * Build the blocking response. Defaults to 403, or 429 with a `Retry-After`
   * for a throttle.
   */
  onBlocked?: (c: Context, decision: Decision) => Response | Promise<Response>;
}

/**
 * Where the decision is stashed on the Hono context.
 *
 * Read it with `c.get('webdecoy')` — in monitor mode this is the only place the
 * verdict surfaces, and monitor is the default.
 */
export const WEBDECOY_CONTEXT_KEY = 'webdecoy';

declare module 'hono' {
  interface ContextVariableMap {
    webdecoy?: Decision;
  }
}

export function webdecoy(options: WebDecoyHonoOptions = {}): MiddlewareHandler {
  const { onBlocked, ...guardOptions } = options;
  const guard = createFetchGuard(guardOptions);

  return async (c: Context, next: Next): Promise<Response | void> => {
    if (guard.skips(new URL(c.req.url).pathname)) {
      await next();
      return;
    }

    // Workers expose the peer address as a header rather than a socket, and
    // there is no portable accessor across Hono's runtimes — so the guard's
    // trusted-hops default over X-Forwarded-For is what resolves the client,
    // and `trustProxy: 'cloudflare'` is the stronger choice behind Cloudflare.
    const { decision, response } = await guard.check(c.req.raw);
    c.set(WEBDECOY_CONTEXT_KEY, decision);

    if (response) {
      return onBlocked ? await onBlocked(c, decision) : response;
    }

    await next();

    // Honeytoken injection. Hono has already built the response, so this reads
    // and rewrites it — full HTML documents only, and never one whose body the
    // application has already consumed.
    if (c.res) {
      c.res = await guard.decorate(c.res);
    }
  };
}

export type { FetchGuardOptions, Decision } from '@webdecoy/node';
export type { WebDecoyConfig, RequestMetadata, ProtectResult } from '@webdecoy/node';
