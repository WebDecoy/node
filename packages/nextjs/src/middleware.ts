/**
 * Web Decoy Next.js Middleware
 */

import { NextRequest, NextResponse } from 'next/server';
import {
  WebDecoy,
  WebDecoyConfig,
  RequestMetadata,
  ProtectOptions,
  resolveClientIp,
  normalizeIp,
} from '@webdecoy/node';
import type { TrustedProxies, ProtectResult, SDKDetectionResponse } from '@webdecoy/node';

export interface WebDecoyMiddlewareOptions extends ProtectOptions {
  /**
   * Whether a blocking verdict actually blocks. Defaults to `'monitor'`.
   *
   * MONITOR IS THE DEFAULT ON PURPOSE, and this changed in 0.7.0. Before,
   * installing this with an API key began returning 403 to any request whose
   * server-side score cleared `threatScoreThreshold` (default 80), and there was
   * no supported way to watch first — which is a good way to take down a site on
   * the first install.
   *
   * Watch what it would have done, then set `mode: 'enforce'`.
   */
  mode?: 'monitor' | 'enforce';

  /**
   * How many proxies sit between the client and this middleware, or which ones.
   * Defaults to `1` — the hosting platform in front of you.
   *
   * THIS CHANGED IN 0.12.0, and it is a behaviour change worth reading.
   *
   * Before, the middleware read the LEFTMOST `X-Forwarded-For` value. That is
   * the one value in the header the client writes itself, so a single
   * `-H 'X-Forwarded-For: 1.2.3.4'` bought a fresh rate-limit bucket per forged
   * address and put an address of the caller's choosing on every detection we
   * reported. It now reads from the right, past the hops you say you have.
   *
   * Edge middleware has no socket to fall back on, so unlike the Express and
   * Fastify adapters there is no safe "believe nothing" default here — `1` is
   * correct on Vercel and on any single-proxy deployment. Behind a CDN in front
   * of your platform, set `2`. Behind Cloudflare with the origin locked to it,
   * `'cloudflare'` is stronger than counting.
   */
  trustProxy?: TrustedProxies;

  /**
   * Custom function to extract IP address from request.
   *
   * Overrides `trustProxy` entirely — you are choosing the address yourself.
   */
  getIP?: (req: NextRequest) => string;

  /**
   * Custom function to handle blocked requests
   * By default, returns 403 Forbidden JSON response
   */
  /**
   * Called when a request would be blocked.
   *
   * `detection` is the detection response, as before. `decision` is the full
   * typed verdict — `conclusion`, every rule's outcome including the ones that
   * dry-ran or never ran, and `deniedBy('tripwire')` — for handlers that need to
   * know WHY rather than just THAT.
   */
  onBlocked?: (
    req: NextRequest,
    detection: SDKDetectionResponse,
    decision: ProtectResult,
  ) => NextResponse;

  /**
   * Custom function to handle errors
   * By default, logs error and allows request (fail open)
   */
  onError?: (req: NextRequest, error: Error) => NextResponse | null;

  /**
   * Paths to skip protection (e.g., health checks, static assets)
   */
  skipPaths?: string[] | RegExp[];

  /**
   * Path patterns to match for protection
   * Uses Next.js matcher syntax
   */
  matcher?: string[];
}

/**
 * The client IP, as far as we are willing to believe it.
 *
 * `x-real-ip` and `x-vercel-forwarded-for` are consulted only after the
 * forwarding chain comes up empty. Both are written by a proxy in the normal
 * case and by anyone at all otherwise, so they are a fallback for a missing
 * `X-Forwarded-For`, never an override of one.
 */
function resolveIP(req: NextRequest, trustProxy: TrustedProxies | undefined): string {
  const fromChain = resolveClientIp({
    headers: req.headers,
    trustProxy: trustProxy ?? 1,
  });
  if (fromChain) return fromChain;

  return (
    normalizeIp(req.headers.get('x-real-ip')) ??
    normalizeIp(req.headers.get('x-vercel-forwarded-for')?.split(',').pop()) ??
    '127.0.0.1'
  );
}

/**
 * Default blocked request handler
 */
function defaultOnBlocked(req: NextRequest, detection: SDKDetectionResponse): NextResponse {
  return NextResponse.json(
    {
      error: 'Forbidden',
      message: 'Access denied by Web Decoy protection',
      detection_id: detection.detection_id,
    },
    { status: 403 }
  );
}

/**
 * Default error handler
 */
function defaultOnError(req: NextRequest, error: Error): NextResponse | null {
  console.error('[WebDecoy] Middleware error:', error);
  // Fail open - allow the request to continue
  return null;
}

/**
 * Check if path should be skipped
 */
function shouldSkipPath(path: string, skipPaths?: string[] | RegExp[]): boolean {
  if (!skipPaths || skipPaths.length === 0) {
    return false;
  }

  return skipPaths.some((pattern) => {
    if (typeof pattern === 'string') {
      return path === pattern || path.startsWith(pattern);
    }
    return pattern.test(path);
  });
}

/**
 * Create Next.js middleware for Web Decoy protection
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { withWebDecoy } from '@webdecoy/nextjs';
 * import { rateLimit } from '@webdecoy/node';
 *
 * export default withWebDecoy({
 *   rules: [rateLimit({ max: 100, window: 60 })],
 *   skipPaths: ['/_next', '/favicon.ico'],
 * });
 *
 * export const config = {
 *   matcher: ['/api/:path*', '/protected/:path*'],
 * };
 * ```
 */
export function withWebDecoy(
  config: WebDecoyConfig & WebDecoyMiddlewareOptions
): (req: NextRequest) => Promise<NextResponse> {
  const sdk = new WebDecoy(config);

  const getIP = config.getIP || ((req: NextRequest) => resolveIP(req, config.trustProxy));
  const onBlocked = config.onBlocked || defaultOnBlocked;
  const mode = config.mode ?? 'monitor';
  const onError = config.onError || defaultOnError;
  const skipPaths = config.skipPaths;

  return async (req: NextRequest): Promise<NextResponse> => {
    try {
      const pathname = req.nextUrl.pathname;

      // Skip protection for certain paths
      if (shouldSkipPath(pathname, skipPaths)) {
        return NextResponse.next();
      }

      // Extract request metadata
      const headers: Record<string, string> = {};
      req.headers.forEach((value, key) => {
        headers[key] = value;
      });

      const metadata: RequestMetadata = {
        method: req.method,
        path: pathname,
        ip: getIP(req),
        user_agent: req.headers.get('user-agent') || undefined,
        headers,
        timestamp: Date.now(),
      };

      // Protect the request (rules are evaluated inside protect())
      const result = await sdk.protect(metadata, {
        threshold: config.threshold,
        skipLocalAnalysis: config.skipLocalAnalysis,
        metadata: config.metadata,
      });

      // Monitor mode: record the verdict, change nothing. Checked before the
      // rule branches so a THROTTLE is an observation too. The annotation still
      // rides on the REQUEST, so the application can act on it itself.
      if (mode === 'monitor') {
        const monitorHeaders = new Headers(req.headers);
        monitorHeaders.delete('x-webdecoy-decision');
        monitorHeaders.delete('x-webdecoy-detection-id');
        monitorHeaders.delete('x-webdecoy-would-block');
        if (result.detection) {
          monitorHeaders.set('x-webdecoy-decision', result.detection.decision || '');
          monitorHeaders.set('x-webdecoy-detection-id', result.detection.detection_id || '');
        }
        monitorHeaders.set('x-webdecoy-would-block', String(!result.allowed));
        return NextResponse.next({ request: { headers: monitorHeaders } });
      }

      // Handle rule engine results for specific HTTP responses
      if (!result.allowed && result.ruleResult) {
        const rr = result.ruleResult;

        if (rr.action === 'THROTTLE') {
          const retryAfter = rr.metadata?.retryAfter ?? 60;
          return NextResponse.json(
            {
              error: 'Too Many Requests',
              message: rr.reason || 'Rate limit exceeded',
              retry_after: retryAfter,
            },
            {
              status: 429,
              headers: { 'Retry-After': String(retryAfter) },
            }
          );
        }

        if (rr.action === 'DENY') {
          return NextResponse.json(
            {
              error: 'Forbidden',
              message: rr.reason || 'Access denied by rule',
              rule: rr.rule,
            },
            { status: 403 }
          );
        }
      }

      // Handle the result
      if (result.allowed) {
        // Annotate the REQUEST, so the application sees it.
        //
        // This previously did `NextResponse.next()` then `response.headers.set()`,
        // which sets RESPONSE headers: the exact opposite of what its own comment
        // said. Two consequences, both bad. The application never saw the
        // annotation — route handlers and server components read request headers —
        // so the feature did not work at all. And the annotation was sent to the
        // browser, publishing our decision and detection id to the client we had
        // just judged.
        //
        // In Next.js middleware, forwarding to the app requires passing headers
        // through the `request` option; mutating the response is not the same
        // thing and never was.
        const requestHeaders = new Headers(req.headers);
        // Drop any inbound copy first. An application that trusts these must not
        // be talkable-into by the request being judged, and `set` only covers the
        // branch where we have a detection to write.
        requestHeaders.delete('x-webdecoy-decision');
        requestHeaders.delete('x-webdecoy-detection-id');
        if (result.detection) {
          requestHeaders.set('x-webdecoy-decision', result.detection.decision || '');
          requestHeaders.set('x-webdecoy-detection-id', result.detection.detection_id || '');
        }
        return NextResponse.next({ request: { headers: requestHeaders } });
      } else {
        return onBlocked(req, result.detection, result);
      }
    } catch (error) {
      const errorResponse = onError(req, error as Error);
      if (errorResponse) {
        return errorResponse;
      }
      return NextResponse.next(); // Fail open
    }
  };
}

export interface WithBotProtectionOptions extends WebDecoyMiddlewareOptions {
  /**
   * Block threshold (0-100). Requests with scores above this are blocked.
   * Default: 80
   */
  blockThreshold?: number;
}

/**
 * Higher-order function to wrap API route handlers with bot protection
 *
 * @example
 * ```typescript
 * // pages/api/protected.ts
 * import { withBotProtection } from '@webdecoy/nextjs';
 *
 * async function handler(req: NextApiRequest, res: NextApiResponse) {
 *   res.json({ data: 'protected' });
 * }
 *
 * export default withBotProtection(handler, {
 *   apiKey: process.env.WEBDECOY_API_KEY!,
 *   blockThreshold: 70,
 * });
 * ```
 */
export function withBotProtection<T extends (...args: any[]) => any>(
  handler: T,
  config: WebDecoyConfig & WithBotProtectionOptions
): T {
  const sdk = new WebDecoy(config);
  const threshold = config.blockThreshold ?? 80;

  return (async (...args: Parameters<T>) => {
    const [req, res] = args;

    try {
      // A Pages API route runs on Node, so there is a socket here and the safe
      // default the edge middleware cannot have applies: believe no forwarding
      // header unless the caller says how many proxies wrote it.
      const peer = req.socket?.remoteAddress;
      const ip =
        resolveClientIp({ headers: req.headers, peer, trustProxy: config.trustProxy }) ??
        normalizeIp(peer) ??
        '127.0.0.1';

      const metadata: RequestMetadata = {
        method: req.method || 'GET',
        path: req.url || '/',
        ip,
        user_agent: req.headers['user-agent'],
        headers: req.headers as Record<string, string>,
        timestamp: Date.now(),
      };

      const result = await sdk.protect(metadata, {
        threshold,
        skipLocalAnalysis: config.skipLocalAnalysis,
        metadata: config.metadata,
      });

      if (!result.allowed) {
        // Handle rule engine specific responses
        if (result.ruleResult?.action === 'THROTTLE') {
          const retryAfter = result.ruleResult.metadata?.retryAfter ?? 60;
          res.setHeader('Retry-After', String(retryAfter));
          return res.status(429).json({
            error: 'Too Many Requests',
            message: result.ruleResult.reason || 'Rate limit exceeded',
            retry_after: retryAfter,
          });
        }

        return res.status(403).json({
          error: 'Forbidden',
          message: 'Access denied by Web Decoy protection',
          detection_id: result.detection?.detection_id,
        });
      }

      // Attach detection info to request
      (req as any).webdecoy = result.detection;
    } catch (error) {
      console.error('[WebDecoy] Protection error:', error);
      // Fail open
    }

    return handler(...args);
  }) as T;
}
