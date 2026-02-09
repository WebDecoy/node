/**
 * Web Decoy Express Middleware
 */

import { Request, Response, NextFunction } from 'express';
import { WebDecoy, WebDecoyConfig, RequestMetadata, ProtectOptions } from '@webdecoy/node';

export interface WebDecoyMiddlewareOptions extends ProtectOptions {
  /**
   * Custom function to extract IP address from request
   * By default, uses req.ip or x-forwarded-for header
   */
  getIP?: (req: Request) => string;

  /**
   * Custom function to handle blocked requests
   * By default, returns 403 Forbidden
   */
  onBlocked?: (req: Request, res: Response, detection: any) => void;

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
function defaultOnBlocked(req: Request, res: Response, detection: any): void {
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
        return next();
      } else {
        // Block the request
        return onBlocked(req, res, result.detection);
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
    }
  }
}
