/**
 * Next.js App Router captcha route handlers.
 *
 * Returns Web `Request` → `Response` handlers for a catch-all route. Mount at
 * `app/__webdecoy/[...webdecoy]/route.ts`:
 *
 * @example
 * ```ts
 * // app/__webdecoy/[...webdecoy]/route.ts
 * import { createCaptchaHandler } from '@webdecoy/nextjs';
 * export const { GET, POST } = createCaptchaHandler({ secret: process.env.WEBDECOY_SECRET });
 * ```
 */

import {
  createCaptchaEndpoints,
  resolveClientIp,
  normalizeIp,
  type CaptchaEndpointsOptions,
  type TrustedProxies,
} from '@webdecoy/node';

/**
 * The captcha endpoints rate-limit and score by IP, so they need the same
 * answer the middleware gets — a forgeable one here would let a solver farm
 * mint challenges under an address per request. Defaults to one trusted hop for
 * the same reason the middleware does: a route handler has no socket to fall
 * back on.
 */
function getIP(headers: Headers, trustProxy: TrustedProxies | undefined): string {
  const fromChain = resolveClientIp({ headers, trustProxy: trustProxy ?? 1 });
  if (fromChain) return fromChain;
  return (
    normalizeIp(headers.get('x-real-ip')) ??
    normalizeIp(headers.get('x-vercel-forwarded-for')?.split(',').pop()) ??
    '127.0.0.1'
  );
}

export interface NextCaptchaOptions extends CaptchaEndpointsOptions {
  /**
   * How many proxies sit between the client and this handler, or which ones.
   * Defaults to `1`. Same meaning as the middleware's option.
   */
  trustProxy?: TrustedProxies;
}

function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

export interface NextCaptchaHandlers {
  GET: (req: Request) => Promise<Response>;
  POST: (req: Request) => Promise<Response>;
}

export function createCaptchaHandler(options?: NextCaptchaOptions): NextCaptchaHandlers {
  const endpoints = createCaptchaEndpoints(options);

  async function handler(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const query: Record<string, string | undefined> = {};
    url.searchParams.forEach((value, key) => {
      query[key] = value;
    });

    let body: unknown;
    if (req.method.toUpperCase() === 'POST') {
      try {
        body = await req.json();
      } catch {
        body = undefined;
      }
    }

    const headers = headersToRecord(req.headers);
    const result = await endpoints.handle({
      method: req.method,
      pathname: url.pathname,
      query,
      headers,
      body,
      ip: getIP(req.headers, options?.trustProxy),
    });

    if (!result) {
      return new Response(JSON.stringify({ error: 'not_found' }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      });
    }

    return new Response(JSON.stringify(result.body), {
      status: result.status,
      headers: result.headers,
    });
  }

  return { GET: handler, POST: handler };
}
