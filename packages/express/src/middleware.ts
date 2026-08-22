/**
 * Web Decoy Express Middleware
 */

import { Request, Response, NextFunction } from 'express';
import { WebDecoy, WebDecoyConfig, RequestMetadata, ProtectOptions } from '@webdecoy/node';
import type {
  EdgeVerdict,
  SiteHoneytoken,
  TrustedProxies,
  ProtectResult,
  SDKDetectionResponse,
} from '@webdecoy/node';
import {
  siteHoneytoken,
  injectHoneytokenLink,
  isInjectableHtml,
  tripwire,
  resolveClientIp,
  normalizeIp,
} from '@webdecoy/node';

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
   *    * Nobody adopts a defence by having it break their site on the first install.
   * Watch what it would have done, then set `mode: 'enforce'`.
   */
  mode?: 'monitor' | 'enforce';

  /**
   * Inject a hidden honeytoken link into HTML responses, and arm the tripwire it
   * points at. Defaults to **on** when an apiKey is present.
   *
   * The SDK used to generate a honeytoken and ask the developer to embed it.
   * Almost nobody does, and an unplaced link is a trap nothing can walk into.
   *
   * A trap hit is the only detection here that needs no score, no JavaScript, no
   * fingerprint and no IP. It is also the only one that scores: honeypot signals
   * carry the highest weight in the threat score, while a User-Agent — all a
   * rule-less install can otherwise report — carries nearly none.
   *
   * Set `false` to opt out, or place the link yourself for apps that stream.
   */
  honeytoken?: boolean;

  /**
   * How much of the `X-Forwarded-For` chain to believe.
   *
   * Leave this unset and Express decides: `req.ip` already honours the app's own
   * `trust proxy` setting, which defaults to the socket address. Set it to
   * override that for WebDecoy alone — a number of trusted hops, `'cloudflare'`,
   * or CIDRs of your proxies.
   *
   * THIS CHANGED IN 0.12.0, and it is a behaviour change worth reading.
   *
   * Before, the middleware read the leftmost `X-Forwarded-For` value and called
   * it the client — the one value in that header the client writes itself. A
   * single `-H 'X-Forwarded-For: 1.2.3.4'` bought a fresh rate-limit bucket per
   * forged address and put an address of the caller's choosing on every
   * detection we reported.
   *
   * If your app is behind a proxy and does not already set `trust proxy`, set
   * this, or every request will be attributed to the proxy.
   */
  trustProxy?: TrustedProxies;

  /**
   * Custom function to extract IP address from request.
   *
   * Overrides `trustProxy` entirely — you are choosing the address yourself.
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
   *
   * `decision` is the full typed verdict — `conclusion`, every rule's outcome
   * including the ones that dry-ran or never ran, and `deniedBy('tripwire')` —
   * for handlers that need to know WHY rather than just THAT.
   */
  onBlocked?: (
    req: Request,
    res: Response,
    detection: SDKDetectionResponse,
    next: NextFunction,
    decision: ProtectResult,
  ) => void;

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
 * The client IP, as far as we are willing to believe it.
 *
 * With no `trustProxy` we defer to `req.ip`, because Express has already
 * answered this question: it applies the app's `trust proxy` setting and falls
 * back to the socket address when there isn't one. Deferring means an app that
 * has configured its proxies correctly does not have to configure them twice,
 * and an app that hasn't gets the peer address instead of a forgeable header.
 */
function resolveIP(req: Request, trustProxy: TrustedProxies | undefined): string {
  const peer = req.socket?.remoteAddress;

  if (trustProxy === undefined) {
    return normalizeIp(req.ip) ?? normalizeIp(peer) ?? '127.0.0.1';
  }

  return (
    resolveClientIp({ headers: req.headers, peer, trustProxy }) ??
    normalizeIp(peer) ??
    '127.0.0.1'
  );
}

/**
 * Default blocked request handler
 */
function defaultOnBlocked(
  req: Request,
  res: Response,
  detection: SDKDetectionResponse,
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

  const getIP = config.getIP || ((req: Request) => resolveIP(req, config.trustProxy));
  const onBlocked = config.onBlocked || defaultOnBlocked;
  const mode = config.mode ?? 'monitor';

  // Honeytoken. Derived from the API key so every replica computes the
  // same path without coordinating — a random per-process token would advertise
  // a link whose tripwire only one replica had armed.
  //
  // Resolution is async (WebCrypto HMAC, so this still runs on edge runtimes),
  // and requests served before it settles simply carry no link. That is a few
  // milliseconds at boot against the alternative of blocking startup on crypto.
  const honeytokenEnabled = (config.honeytoken ?? true) && Boolean(config.apiKey);
  let token: SiteHoneytoken | null = null;
  if (honeytokenEnabled) {
    void siteHoneytoken({ secret: config.apiKey as string })
      .then((t) => {
        token = t;
        // Arm the path we are about to advertise. Without this the link is bait
        // with no trap behind it — a crawler follows it and nothing happens.
        sdk.addRule(tripwire({ paths: t.activePaths, includeDefaults: false }));
      })
      .catch(() => {
        // Deriving the token is not worth a failed boot. No token, no injection.
      });
  }
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

      // Honeytoken injection.
      //
      // Buffers the body only for full HTML documents and rewrites it once. The
      // guards below are not defensive padding — each one is a way this could
      // corrupt a customer's response, which is a far worse failure than a
      // missed detection:
      //
      //   - non-HTML is left untouched, so an anchor never lands in JSON
      //   - a committed response is left alone, because headers are already sent
      //   - Content-Length is corrected, or the client truncates the body
      //   - anything thrown falls back to the original write
      if (token) {
        const ht = token;
        const originalWrite = res.write.bind(res);
        const originalEnd = res.end.bind(res);
        const chunks: Buffer[] = [];
        let intercepting: boolean | null = null;

        // Whether the body can still be rewritten.
        //
        // `headersSent` is deliberately NOT a blocker. Streaming frameworks —
        // Angular SSR, Nuxt, anything that calls res.writeHead() then pipes —
        // commit headers before the first byte of body, so requiring
        // !headersSent silently disabled injection for exactly the apps most
        // likely to be serving server-rendered HTML. Found on a real Angular SSR
        // site: page rendered, nothing injected, no error.
        //
        // What actually matters is whether a Content-Length has been committed
        // that we can no longer correct. Under chunked encoding none is declared,
        // so the body is free to change; with a committed length, growing the
        // body would truncate it at the client, so leave it alone.
        const shouldIntercept = (): boolean => {
          if (intercepting === null) {
            const isHtml = isInjectableHtml(res.getHeader('content-type') as string);
            const lengthCommitted =
              res.headersSent && res.getHeader('content-length') !== undefined;
            intercepting = isHtml && !lengthCommitted;
          }
          return intercepting;
        };

        (res as any).write = function (chunk: any, ...rest: any[]): boolean {
          if (!shouldIntercept()) return originalWrite(chunk, ...rest);
          if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          return true;
        };

        (res as any).end = function (chunk: any, ...rest: any[]): any {
          try {
            if (!shouldIntercept()) return originalEnd(chunk, ...rest);
            if (chunk && typeof chunk !== 'function') {
              chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            }
            const body = injectHoneytokenLink(Buffer.concat(chunks).toString('utf8'), ht.linkHtml);
            const out = Buffer.from(body, 'utf8');
            // The body grew; a stale Content-Length truncates it at the client.
            // Only settable while headers are still open — under chunked encoding
            // there is nothing to correct, which is why that path is allowed.
            if (!res.headersSent) res.setHeader('Content-Length', String(out.length));
            return originalEnd(out);
          } catch {
            // Never let injection cost the response.
            return originalEnd(chunk, ...rest);
          }
        };
      }

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
        // And what the edge validator said, typed. A handler can branch on
        // req.webdecoyEdge.isScript instead of string-matching x-wd-class, and
        // `present: false` tells it the edge was never in front of this request —
        // which is no information, not a clean bill of health.
        (req as any).webdecoyEdge = result.edge;
        return next();
      } else {
        // Block the request
        return onBlocked(req, res, result.detection, next, result);
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
      /** What the edge validator said about this request. */
      webdecoyEdge?: EdgeVerdict;
    }
  }
}
