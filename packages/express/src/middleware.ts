/**
 * Web Decoy Express Middleware
 */

import { Request, Response, NextFunction } from 'express';
import { WebDecoy, WebDecoyConfig, RequestMetadata, ProtectOptions } from '@webdecoy/node';
import type { EdgeVerdict } from '@webdecoy/node';

export interface WebDecoyMiddlewareOptions extends ProtectOptions {
  /**
   * Whether a blocking verdict actually blocks. Defaults to `'monitor'`.
   *
   * MONITOR IS THE DEFAULT ON PURPOSE, and this changed in 0.7.0.
   *
   * Before, installing this middleware with an API key began returning 403 to
   * any request whose server-side score cleared `threatScoreThreshold` — which
   * defaults to 80 — and there was no supported way to watch first. `dryRun` on
   * a rule governs that rule, not the score, and `onBlocked` did not receive
   * `next`, so "record it and serve the request anyway" could not be expressed.
   *
   * Found by installing it on a live site that takes payments: the homepage
   * returned `{"error":"Forbidden"}` on the first request, as did an ordinary
   * `python-requests` user agent.
   *
   * Nobody adopts a defence by having it break their site on the first install.
   * Watch what it would have done, then set `mode: 'enforce'`.
   */
  mode?: 'monitor' | 'enforce';

  /**
   * Custom function to extract IP address from request
   * By default, uses req.ip or x-forwarded-for header
   */
  getIP?: (req: Request) => string;

  /**
   * Custom function to handle blocked requests
   * By default, returns 403 Forbidden
   */
  /**
   * Called when a request would be blocked.
   *
   * `next` is passed so a handler can record the verdict and continue — the
   * omission that made monitoring impossible. Call exactly one of `next()` or a
   * response method.
   */
  onBlocked?: (req: Request, res: Response, detection: any, next: NextFunction) => void;

  /**
   * Custom function to handle errors
   * By default, logs error and allows request (fail open)
   */
  onError?: (req: Request, res: Response, error: Error) => void;

  /**
   * Paths to skip protection (e.g., health checks, static assets)
   */
  skipPaths?: string[] | RegExp[];

  /**
   * Enable TLS info extraction from the request
   * Requires proxy or custom setup to expose TLS details
   */
  extractTLS?: boolean;
}

/**
 * Default IP extraction function
 * Handles various common proxy headers
 */
function defaultGetIP(req: Request): string {
  // Check X-Forwarded-For header (common with proxies)
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    return ips.split(',')[0].trim();
  }

  // Check X-Real-IP header
  const realIP = req.headers['x-real-ip'];
  if (realIP) {
    return Array.isArray(realIP) ? realIP[0] : realIP;
  }

  // Fall back to req.ip
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Default blocked request handler
 */
function defaultOnBlocked(
  req: Request,
  res: Response,
  detection: any,
  _next: NextFunction,
): void {
  res.status(403).json({
    error: 'Forbidden',
    message: 'Access denied by Web Decoy protection',
    detection_id: detection.detection_id,
  });
}

/**
 * Default error handler
 */
function defaultOnError(req: Request, res: Response, error: Error): void {
  console.error('[WebDecoy] Middleware error:', error);
  // Fail open - allow the request to continue
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
 * Create Express middleware for Web Decoy protection
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { webdecoy } from '@webdecoy/express';
 * import { rateLimit } from '@webdecoy/node';
 *
 * const app = express();
 *
 * // Rate limiting only (no API key required)
 * app.use(webdecoy({
 *   rules: [rateLimit({ max: 100, window: 60 })],
 *   skipPaths: ['/health', '/static'],
 * }));
 *
 * // Full protection with API key
 * app.use(webdecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY,
 *   rules: [rateLimit({ max: 100, window: 60 })],
 * }));
 * ```
 */
export function webdecoy(
  config: WebDecoyConfig & WebDecoyMiddlewareOptions
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const sdk = new WebDecoy(config);

  const getIP = config.getIP || defaultGetIP;
  const onBlocked = config.onBlocked || defaultOnBlocked;
  const mode = config.mode ?? 'monitor';
  const onError = config.onError || defaultOnError;
  const skipPaths = config.skipPaths;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Skip protection for certain paths
      if (shouldSkipPath(req.path, skipPaths)) {
        return next();
      }

      // Extract request metadata
      const metadata: RequestMetadata = {
        method: req.method,
        path: req.path,
        ip: getIP(req),
        user_agent: req.headers['user-agent'],
        headers: req.headers as Record<string, string>,
        timestamp: Date.now(),
      };

      // Protect the request (rules are evaluated inside protect())
      const result = await sdk.protect(metadata, {
        threshold: config.threshold,
        skipLocalAnalysis: config.skipLocalAnalysis,
        metadata: config.metadata,
      });

      // Monitor mode: the verdict is recorded and reported, and the request is
      // served exactly as it would have been.
      //
      // Checked BEFORE the rule branches below, not after. A rate-limit rule
      // returning 429 is as much of an unasked-for surprise as a 403, so
      // monitor has to mean "changes nothing", not "changes nothing except the
      // rules". An earlier draft of this put the check after them and would
      // have shipped exactly the bug it exists to fix.
      if (mode === 'monitor') {
        (req as any).webdecoy = result.detection;
        (req as any).webdecoyEdge = result.edge;
        (req as any).webdecoyWouldBlock = !result.allowed;
        return next();
      }

      // Handle rule engine results for specific HTTP responses
      if (!result.allowed && result.ruleResult) {
        const rr = result.ruleResult;

        if (rr.action === 'THROTTLE') {
          const retryAfter = rr.metadata?.retryAfter ?? 60;
          res.setHeader('Retry-After', String(retryAfter));
          res.status(429).json({
            error: 'Too Many Requests',
            message: rr.reason || 'Rate limit exceeded',
            retry_after: retryAfter,
          });
          return;
        }

        if (rr.action === 'DENY') {
          res.status(403).json({
            error: 'Forbidden',
            message: rr.reason || 'Access denied by rule',
            rule: rr.rule,
          });
          return;
        }
      }

      // Handle the result
      if (result.allowed) {
        // Attach detection info to request for downstream use
        (req as any).webdecoy = result.detection;
        // And what the edge validator said, typed (#481). A handler can branch on
        // req.webdecoyEdge.isScript instead of string-matching x-wd-class, and
        // `present: false` tells it the edge was never in front of this request —
        // which is no information, not a clean bill of health.
        (req as any).webdecoyEdge = result.edge;
        return next();
      } else {
        // Block the request
        return onBlocked(req, res, result.detection, next);
      }
    } catch (error) {
      onError(req, res, error as Error);
      return next(); // Fail open
    }
  };
}

/**
 * Type augmentation for Express Request
 * Adds webdecoy property to req object
 */
declare global {
  namespace Express {
    interface Request {
      webdecoy?: {
        decision: string;
        confidence: number;
        threat_level: string;
        bot_detected: boolean;
        bot_type?: string;
        detection_id: string;
        rule_enforced: boolean;
      };
      /** What the edge validator said about this request (#481). */
      webdecoyEdge?: EdgeVerdict;
    }
  }
}
