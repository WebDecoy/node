/**
 * Web Decoy Next.js Middleware
 */

import { NextRequest, NextResponse } from 'next/server';
import { WebDecoy, WebDecoyConfig, RequestMetadata, ProtectOptions } from '@webdecoy/node';

export interface WebDecoyMiddlewareOptions extends ProtectOptions {
  /**
   * Custom function to extract IP address from request
   * By default, uses x-forwarded-for or x-real-ip headers
   */
  getIP?: (req: NextRequest) => string;

  /**
   * Custom function to handle blocked requests
   * By default, returns 403 Forbidden JSON response
   */
  onBlocked?: (req: NextRequest, detection: any) => NextResponse;

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
 * Default IP extraction function for Next.js
 */
function defaultGetIP(req: NextRequest): string {
  // Check X-Forwarded-For header (common with Vercel and proxies)
  const forwardedFor = req.headers.get('x-forwarded-for');
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }

  // Check X-Real-IP header
  const realIP = req.headers.get('x-real-ip');
  if (realIP) {
    return realIP;
  }

  // Vercel provides this
  const vercelIP = req.headers.get('x-vercel-forwarded-for');
  if (vercelIP) {
    return vercelIP.split(',')[0].trim();
  }

  return '127.0.0.1';
}

/**
 * Default blocked request handler
 */
function defaultOnBlocked(req: NextRequest, detection: any): NextResponse {
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

  const getIP = config.getIP || defaultGetIP;
  const onBlocked = config.onBlocked || defaultOnBlocked;
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
        // Add detection info to request headers for downstream use
        const response = NextResponse.next();
        if (result.detection) {
          response.headers.set('x-webdecoy-decision', result.detection.decision || '');
          response.headers.set('x-webdecoy-detection-id', result.detection.detection_id || '');
        }
        return response;
      } else {
        return onBlocked(req, result.detection);
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
      // Extract IP from various sources
      const forwardedFor = req.headers['x-forwarded-for'];
      const ip = forwardedFor
        ? (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor).split(',')[0].trim()
        : req.headers['x-real-ip'] || req.socket?.remoteAddress || '127.0.0.1';

      const metadata: RequestMetadata = {
        method: req.method || 'GET',
        path: req.url || '/',
        ip: typeof ip === 'string' ? ip : '127.0.0.1',
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
