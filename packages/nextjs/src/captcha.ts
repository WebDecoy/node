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

import { createCaptchaEndpoints, type CaptchaEndpointsOptions } from '@webdecoy/node';

function getIP(headers: Headers): string {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  return (
    headers.get('x-real-ip') ||
    headers.get('x-vercel-forwarded-for') ||
    '127.0.0.1'
  );
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

export function createCaptchaHandler(options?: CaptchaEndpointsOptions): NextCaptchaHandlers {
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
      ip: getIP(req.headers),
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
