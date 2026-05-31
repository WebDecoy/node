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
import { createCaptchaEndpoints, type CaptchaEndpointsOptions } from '@webdecoy/node';

function getIP(req: Request): string {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    return ips.split(',')[0].trim();
  }
  const realIP = req.headers['x-real-ip'];
  if (realIP) return Array.isArray(realIP) ? realIP[0] : realIP;
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

function normalizeQuery(query: Request['query']): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(query)) {
    out[k] = Array.isArray(v) ? String(v[0]) : typeof v === 'string' ? v : undefined;
  }
  return out;
}

export function webdecoyCaptcha(options?: CaptchaEndpointsOptions): RequestHandler {
  const endpoints = createCaptchaEndpoints(options);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const result = await endpoints.handle({
      method: req.method,
      pathname: req.path,
      query: normalizeQuery(req.query),
      headers: req.headers as Record<string, string>,
      body: req.body,
      ip: getIP(req),
    });

    if (!result) {
      next();
      return;
    }

    res.status(result.status);
    for (const [k, v] of Object.entries(result.headers)) res.setHeader(k, v);
    res.json(result.body);
  };
}
