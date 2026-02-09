/**
 * Web Decoy Fastify Plugin
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import { WebDecoy, WebDecoyConfig, RequestMetadata, ProtectOptions } from '@webdecoy/node';

export interface WebDecoyPluginOptions extends ProtectOptions {
  /**
   * Custom function to extract IP address from request
   * By default, uses request.ip or x-forwarded-for header
   */
  getIP?: (req: FastifyRequest) => string;

  /**
   * Custom function to handle blocked requests
   * By default, returns 403 Forbidden
   */
  onBlocked?: (req: FastifyRequest, reply: FastifyReply, detection: any) => void;

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
 * Default IP extraction function for Fastify
 */
function defaultGetIP(req: FastifyRequest): string {
  // Fastify provides req.ip which handles x-forwarded-for
  return req.ip || '127.0.0.1';
}

/**
 * Default blocked request handler
 */
function defaultOnBlocked(req: FastifyRequest, reply: FastifyReply, detection: any): void {
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

  const getIP = options.getIP || defaultGetIP;
  const onBlocked = options.onBlocked || defaultOnBlocked;
  const onError = options.onError || defaultOnError;
  const skipPaths = options.skipPaths;

  // Add decorator for webdecoy property
  fastify.decorateRequest('webdecoy', null);

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
        timestamp: Date.now(),
      };

      // Protect the request (rules are evaluated inside protect())
      const result = await sdk.protect(metadata, {
        threshold: options.threshold,
        skipLocalAnalysis: options.skipLocalAnalysis,
        metadata: options.metadata,
      });

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
        req.webdecoy = result.detection as WebDecoyDetection;
      } else {
        // Block the request
        onBlocked(req, reply, result.detection);
      }
    } catch (error) {
      onError(req, reply, error as Error);
      // Fail open - continue with the request
    }
  });
}

export const webdecoyPlugin = fp(webdecoyPluginImpl, {
  fastify: '>=4.0.0',
  name: '@webdecoy/fastify',
});

export default webdecoyPlugin;
