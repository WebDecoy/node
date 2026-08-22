/**
 * Web Decoy Fastify Plugin
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import {
  WebDecoy,
  WebDecoyConfig,
  RequestMetadata,
  ProtectOptions,
  siteHoneytoken,
  injectHoneytokenLink,
  isInjectableHtml,
  tripwire,
  resolveClientIp,
  normalizeIp,
} from '@webdecoy/node';
import type {
  EdgeVerdict,
  SiteHoneytoken,
  TrustedProxies,
  ProtectResult,
  SDKDetectionResponse,
} from '@webdecoy/node';

export interface WebDecoyPluginOptions extends ProtectOptions {
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
   * Applies to buffered responses — `reply.send(html)`, `@fastify/view`, and
   * anything else that hands Fastify a string or Buffer. Streamed replies are
   * left untouched and logged once; see the `onSend` hook for why.
   */
  honeytoken?: boolean;

  /**
   * How much of the `X-Forwarded-For` chain to believe.
   *
   * Leave this unset and Fastify decides: `request.ip` already honours the
   * server's own `trustProxy` option, which defaults to the socket address. Set
   * it to override that for WebDecoy alone — a number of trusted hops,
   * `'cloudflare'`, or CIDRs of your proxies.
   *
   * Fastify's default was already the safe one, so unlike the Express and
   * Next.js adapters nothing changes here in 0.12.0. The option exists so all
   * three adapters answer the question the same way.
   */
  trustProxy?: TrustedProxies;

  /**
   * Custom function to extract IP address from request.
   *
   * Overrides `trustProxy` entirely — you are choosing the address yourself.
   */
  getIP?: (req: FastifyRequest) => string;

  /**
   * Called when a request would be blocked.
   *
   * `detection` is the detection response, as before. `decision` is the full
   * typed verdict — `conclusion`, every rule's outcome including the ones that
   * dry-ran or never ran, and `deniedBy('tripwire')` — for handlers that need to
   * know WHY rather than just THAT.
   */
  onBlocked?: (
    req: FastifyRequest,
    reply: FastifyReply,
    detection: SDKDetectionResponse,
    decision: ProtectResult,
  ) => void;

  /**
   * Custom function to handle errors
   * By default, logs error and allows request (fail open)
   */
  onError?: (req: FastifyRequest, reply: FastifyReply, error: Error) => void;

  /**
   * Paths to skip protection (e.g., health checks, static assets)
   */
  skipPaths?: string[] | RegExp[];
}

/**
 * The client IP, as far as we are willing to believe it.
 *
 * With no `trustProxy` we defer to `request.ip`, which Fastify derives from its
 * own `trustProxy` server option and which falls back to the socket address.
 * Deferring means an app that has configured its proxies correctly does not have
 * to configure them twice.
 */
function resolveIP(req: FastifyRequest, trustProxy: TrustedProxies | undefined): string {
  const peer = req.socket?.remoteAddress;

  if (trustProxy === undefined) {
    return normalizeIp(req.ip) ?? normalizeIp(peer) ?? '127.0.0.1';
  }

  return (
    resolveClientIp({
      headers: req.headers as Record<string, string | string[] | undefined>,
      peer,
      trustProxy,
    }) ??
    normalizeIp(peer) ??
    '127.0.0.1'
  );
}

/**
 * Default blocked request handler
 */
function defaultOnBlocked(
  req: FastifyRequest,
  reply: FastifyReply,
  detection: SDKDetectionResponse,
): void {
  reply.status(403).send({
    error: 'Forbidden',
    message: 'Access denied by Web Decoy protection',
    detection_id: detection.detection_id,
  });
}

/**
 * Default error handler
 */
function defaultOnError(req: FastifyRequest, reply: FastifyReply, error: Error): void {
  req.log.error({ err: error }, '[WebDecoy] Plugin error');
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
 * Web Decoy detection info attached to requests
 */
interface WebDecoyDetection {
  decision: string;
  confidence: number;
  threat_level: string;
  bot_detected: boolean;
  bot_type?: string;
  detection_id: string;
  rule_enforced: boolean;
}

// Extend FastifyRequest type
declare module 'fastify' {
  interface FastifyRequest {
    webdecoy?: WebDecoyDetection;
    /**
     * The full typed verdict: `conclusion`, every rule's outcome including the
     * ones that dry-ran or never ran, and `deniedBy()`. Populated in monitor
     * mode too, which is where it matters — that is the only place a verdict
     * surfaces when nothing is blocked.
     */
    webdecoyDecision?: ProtectResult;
    /** What the edge validator said about this request. */
    webdecoyEdge?: EdgeVerdict;
  }
}

/**
 * Fastify plugin for Web Decoy protection
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import webdecoy from '@webdecoy/fastify';
 * import { rateLimit } from '@webdecoy/node';
 *
 * const fastify = Fastify();
 *
 * fastify.register(webdecoy, {
 *   rules: [rateLimit({ max: 100, window: 60 })],
 *   skipPaths: ['/health'],
 * });
 * ```
 */
async function webdecoyPluginImpl(
  fastify: FastifyInstance,
  options: WebDecoyConfig & WebDecoyPluginOptions
): Promise<void> {
  const sdk = new WebDecoy(options);

  const getIP = options.getIP || ((req: FastifyRequest) => resolveIP(req, options.trustProxy));
  const onBlocked = options.onBlocked || defaultOnBlocked;
  const mode = options.mode ?? 'monitor';
  const onError = options.onError || defaultOnError;
  const skipPaths = options.skipPaths;

  // Honeytoken. Derived from the API key so every replica computes the
  // same path without coordinating — a random per-process token would advertise
  // a link whose tripwire only one replica had armed.
  //
  // Resolution is async (WebCrypto HMAC, so this still runs on edge runtimes).
  // Fastify lets us await it here, because plugin registration is already an
  // async boot phase — so unlike Express there is no window where early requests
  // are served without the link.
  const honeytokenEnabled = (options.honeytoken ?? true) && Boolean(options.apiKey);
  let token: SiteHoneytoken | null = null;
  if (honeytokenEnabled) {
    try {
      token = await siteHoneytoken({ secret: options.apiKey as string });
      // Arm the path we are about to advertise. Without this the link is bait
      // with no trap behind it — a crawler follows it and nothing happens.
      sdk.addRule(tripwire({ paths: token.activePaths, includeDefaults: false }));
    } catch {
      // Deriving the token is not worth a failed boot. No token, no injection.
      token = null;
    }
  }

  // Add decorator for webdecoy property
  fastify.decorateRequest('webdecoy', null);
  // The edge validator's verdict, typed, so a handler can branch on
  // request.webdecoyEdge.isScript rather than string-matching x-wd-class.
  fastify.decorateRequest('webdecoyEdge', null);

  // Add preHandler hook for protection
  fastify.addHook('preHandler', async (req, reply) => {
    try {
      // Skip protection for certain paths
      if (shouldSkipPath(req.url, skipPaths)) {
        return;
      }

      // Extract request metadata
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === 'string') {
          headers[key] = value;
        } else if (Array.isArray(value)) {
          headers[key] = value[0];
        }
      }

      const metadata: RequestMetadata = {
        method: req.method,
        path: req.url,
        ip: getIP(req),
        user_agent: req.headers['user-agent'],
        headers,
        // The query is where injection payloads live, and it is not part of
        // the routed path, so attackSignatures() cannot see it otherwise.
        query: req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : undefined,
        timestamp: Date.now(),
      };

      // Protect the request (rules are evaluated inside protect())
      const result = await sdk.protect(metadata, {
        threshold: options.threshold,
        skipLocalAnalysis: options.skipLocalAnalysis,
        metadata: options.metadata,
      });

      // Monitor mode: record the verdict, change nothing. Checked before the
      // rule branches so a THROTTLE is an observation too.
      if (mode === 'monitor') {
        // `webdecoy` is the detection response and has been since 0.1, so it
        // stays what it is. `webdecoyDecision` is the full typed verdict —
        // conclusion, every rule's outcome, deniedBy() — and carries the same
        // name in every adapter, which `webdecoy` cannot.
        req.webdecoy = result.detection as WebDecoyDetection;
        req.webdecoyDecision = result;
        req.webdecoyEdge = result.edge;
        return;
      }

      // Handle rule engine results for specific HTTP responses
      if (!result.allowed && result.ruleResult) {
        const rr = result.ruleResult;

        if (rr.action === 'THROTTLE') {
          const retryAfter = rr.metadata?.retryAfter ?? 60;
          reply.header('Retry-After', String(retryAfter));
          reply.status(429).send({
            error: 'Too Many Requests',
            message: rr.reason || 'Rate limit exceeded',
            retry_after: retryAfter,
          });
          return;
        }

        if (rr.action === 'DENY') {
          reply.status(403).send({
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
        // `webdecoy` is the detection response and has been since 0.1, so it
        // stays what it is. `webdecoyDecision` is the full typed verdict —
        // conclusion, every rule's outcome, deniedBy() — and carries the same
        // name in every adapter, which `webdecoy` cannot.
        req.webdecoy = result.detection as WebDecoyDetection;
        req.webdecoyDecision = result;
        req.webdecoyEdge = result.edge;
      } else {
        // Block the request
        onBlocked(req, reply, result.detection, result);
      }
    } catch (error) {
      onError(req, reply, error as Error);
      // Fail open - continue with the request
    }
  });

  // Honeytoken injection.
  //
  // Fastify's onSend is purpose-built for this: it hands us the finished payload
  // and takes back a replacement, so there is no wrapping of reply internals the
  // way Express requires. Content-Length is recomputed by Fastify from what we
  // return, so a grown body cannot truncate at the client.
  //
  // Each guard below is a way this could corrupt a customer's response, which is
  // a far worse failure than a missed detection:
  //
  //   - non-HTML is left untouched, so an anchor never lands in JSON
  //   - streams are left untouched (see below)
  //   - anything thrown falls back to the original payload
  if (token) {
    const ht = token;
    let warnedAboutStream = false;

    fastify.addHook('onSend', async (_req, reply, payload) => {
      try {
        if (!isInjectableHtml(reply.getHeader('content-type') as string)) return payload;

        // A streamed reply is left alone on purpose. Buffering it to inject a
        // link would trade the customer's streaming behaviour — and its memory
        // profile on large responses — for a hidden anchor, which is not a
        // trade this plugin gets to make silently on their behalf.
        //
        // So it is not silent. The failure this whole issue is about is a
        // defence that looks installed and detects nothing; a log line once per
        // process is what makes the gap visible instead.
        if (payload === null || typeof payload === 'object') {
          if (!warnedAboutStream) {
            warnedAboutStream = true;
            fastify.log.warn(
              '[WebDecoy] HTML is being streamed, so the honeytoken link was not injected. ' +
                'Render to a string, or embed the link yourself: ' +
                `<a href="${ht.primaryPath}" aria-hidden="true" tabindex="-1" rel="nofollow noindex" ` +
                'style="position:absolute;left:-9999px">.</a>',
            );
          }
          return payload;
        }

        if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) return payload;

        const html = Buffer.isBuffer(payload) ? payload.toString('utf8') : payload;
        return injectHoneytokenLink(html, ht.linkHtml);
      } catch {
        // Never let injection cost the response.
        return payload;
      }
    });
  }
}

export const webdecoyPlugin = fp(webdecoyPluginImpl, {
  fastify: '>=4.0.0',
  name: '@webdecoy/fastify',
});

export default webdecoyPlugin;
