/**
 * Express captcha endpoints.
 *
 * Mounts the WebDecoy captcha routes (challenge / verify / score / token verify)
 * under a base path. Requires JSON body parsing (`express.json()`) ahead of it.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { webdecoyCaptcha } from '@webdecoy/express';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(webdecoyCaptcha({ secret: process.env.WEBDECOY_SECRET }));
 * // → GET /__webdecoy/challenge, POST /__webdecoy/verify, /score, /token/verify
 * ```
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
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
 * mint challenges under an address per request.
 */
function getIP(req: Request, trustProxy: TrustedProxies | undefined): string {
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

export interface ExpressCaptchaOptions extends CaptchaEndpointsOptions {
  /**
   * How much of the `X-Forwarded-For` chain to believe. Same meaning and same
   * default as the middleware's option: unset defers to Express's own
   * `trust proxy` setting.
   */
  trustProxy?: TrustedProxies;
}

function normalizeQuery(query: Request['query']): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(query)) {
    out[k] = Array.isArray(v) ? String(v[0]) : typeof v === 'string' ? v : undefined;
  }
  return out;
}

export function webdecoyCaptcha(options?: ExpressCaptchaOptions): RequestHandler {
  const endpoints = createCaptchaEndpoints(options);

  return (req: Request, res: Response, next: NextFunction): void => {
    // Express 4 does not catch a rejected promise from a handler, so an async
    // handler that throws leaves the request hanging until the client times out
    // and logs an unhandled rejection instead of a 500. Kept synchronous, with
    // the rejection routed to the error middleware explicitly.
    void handle(req, res, next).catch(next);
  };

  async function handle(req: Request, res: Response, next: NextFunction): Promise<void> {
    const result = await endpoints.handle({
      method: req.method,
      pathname: req.path,
      query: normalizeQuery(req.query),
      headers: req.headers as Record<string, string>,
      body: req.body,
      ip: getIP(req, options?.trustProxy),
    });

    if (!result) {
      next();
      return;
    }

    res.status(result.status);
    for (const [k, v] of Object.entries(result.headers)) res.setHeader(k, v);
    res.json(result.body);
  }
}
