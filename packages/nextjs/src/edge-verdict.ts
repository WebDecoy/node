/**
 * Read the edge validator's verdict inside a Next.js app (#481).
 *
 * The Cloudflare clearance worker annotates every forwarded request with
 * `x-wd-clearance` and, when the sensor classified the client, `x-wd-class`.
 * Nothing in this SDK read either header until now, so the only thing an
 * application could do with a scoped route was let the edge 403 it — which on
 * public content means 403ing every client that cannot run JavaScript.
 *
 * This is the read side. It works in middleware, route handlers, server
 * components and server actions, because all it needs is a header bag.
 */

import { readEdgeVerdict, type EdgeVerdict } from '@webdecoy/node';

/**
 * Anything that can hand us request headers: a `NextRequest`, a `Request`, the
 * `Headers` object, or the result of `await headers()` in a server component.
 */
type HeaderSource = { headers: Headers } | Headers | { get(name: string): string | null };

const EDGE_HEADERS = ['x-wd-clearance', 'x-wd-class'];

function bagFrom(source: HeaderSource): Record<string, string> {
  const getter: { get(name: string): string | null } =
    'headers' in source && !('get' in source) ? source.headers : (source as { get(name: string): string | null });

  const bag: Record<string, string> = {};
  for (const name of EDGE_HEADERS) {
    const value = getter.get(name);
    if (value) bag[name] = value;
  }
  return bag;
}

/**
 * Parse the edge validator's annotations from a request.
 *
 * @example
 * ```typescript
 * // app/api/search/route.ts
 * import { getEdgeVerdict } from '@webdecoy/nextjs';
 *
 * export async function GET(req: Request) {
 *   const edge = getEdgeVerdict(req);
 *
 *   // Skip the expensive path for scripted traffic — without 403ing it, and
 *   // without touching what a verified crawler sees.
 *   if (edge.isScript) {
 *     return Response.json(await cheapResults(), {
 *       headers: { 'cache-control': 'private, no-store' },
 *     });
 *   }
 *   return Response.json(await fullResults());
 * }
 * ```
 *
 * `present: false` means the edge did not front this request. That is no
 * information — not "human". Do not treat it as a pass.
 *
 * IMPORTANT, and the reason this returns data rather than a response: do NOT vary
 * a **cacheable response body** on this. Cloudflare's default cache key excludes
 * arbitrary request headers and header-based cache keys are Enterprise-only, so
 * the first variant cached for a URL is served to everyone, Googlebot included —
 * and on a cache hit your origin never runs at all. Vary behaviour, or mark the
 * response private, as above.
 */
export function getEdgeVerdict(source: HeaderSource): EdgeVerdict {
  return readEdgeVerdict(bagFrom(source));
}

export type { EdgeVerdict, EdgeClass } from '@webdecoy/node';
