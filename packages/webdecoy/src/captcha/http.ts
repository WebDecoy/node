/**
 * Framework-agnostic HTTP handler for the captcha endpoints.
 *
 * Maps normalized requests to the {@link Captcha} service so each framework
 * adapter (Express/Fastify/Next.js) only has to translate its own req/res into
 * this shape. Routes (under a configurable base path, default `/__webdecoy`):
 *
 *   GET  {base}/challenge?siteKey=   → issue a PoW challenge
 *   POST {base}/verify               → verify a checkbox submission
 *   POST {base}/score                → invisible-mode score
 *   POST {base}/token/verify         → verify an issued token
 */

import { Captcha, type CaptchaOptions } from './service';
import type { Signals } from '../detection/types';

/** Normalized inbound request the adapters construct. */
export interface CaptchaRequest {
  method: string;
  /** URL pathname (no query string). */
  pathname: string;
  query: Record<string, string | undefined>;
  /** Lower-cased headers. */
  headers: Record<string, string>;
  /** Parsed JSON body (for POST routes). */
  body?: unknown;
  /** Resolved client IP. */
  ip: string;
}

/** Normalized response the adapters write back. */
export interface CaptchaHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface CaptchaEndpointsOptions extends CaptchaOptions {
  /** Base path the routes are mounted under (default `/__webdecoy`). */
  basePath?: string;
}

interface VerifyBody {
  siteKey?: string;
  signals?: Signals;
  powSolution?: import('./types').PoWSolution | null;
  signalsJson?: string | null;
  powTiming?: { duration?: number; iterations?: number } | null;
  action?: string;
  token?: string;
}

const JSON_HEADERS = { 'content-type': 'application/json' };

/**
 * Build a captcha request handler. The returned function resolves to a response
 * for a matching route, or `null` when the request is not a captcha route (so
 * middleware can fall through to the next handler).
 */
export function createCaptchaEndpoints(options: CaptchaEndpointsOptions = {}) {
  const { basePath = '/__webdecoy', ...captchaOptions } = options;
  const captcha = new Captcha(captchaOptions);
  const base = basePath.replace(/\/$/, '');

  function route(pathname: string): string | null {
    if (pathname === base) return '/';
    if (pathname.startsWith(base + '/')) return pathname.slice(base.length);
    return null;
  }

  function json(status: number, body: unknown): CaptchaHttpResponse {
    return { status, headers: { ...JSON_HEADERS }, body };
  }

  async function handle(req: CaptchaRequest): Promise<CaptchaHttpResponse | null> {
    const sub = route(req.pathname);
    if (sub === null) return null;

    const method = req.method.toUpperCase();
    const userAgent = req.headers['user-agent'] ?? '';
    const ja3Hash = req.headers['x-ja3-hash'] ?? null;

    // GET {base}/challenge
    if (sub === '/challenge' && method === 'GET') {
      const siteKey = req.query.siteKey ?? 'default';
      return json(200, await captcha.issueChallenge(siteKey, req.ip));
    }

    // POST {base}/verify
    if (sub === '/verify' && method === 'POST') {
      const b = (req.body ?? {}) as VerifyBody;
      const result = await captcha.verify({
        siteKey: b.siteKey ?? 'default',
        ip: req.ip,
        userAgent,
        headers: req.headers,
        signals: b.signals,
        powSolution: b.powSolution ?? null,
        signalsJson: b.signalsJson ?? null,
        powTiming: b.powTiming ?? null,
        ja3Hash,
      });
      return json(200, result);
    }

    // POST {base}/score (invisible mode)
    if (sub === '/score' && method === 'POST') {
      const b = (req.body ?? {}) as VerifyBody;
      const result = await captcha.score({
        siteKey: b.siteKey ?? 'default',
        ip: req.ip,
        userAgent,
        headers: req.headers,
        signals: b.signals,
        powSolution: b.powSolution ?? null,
        signalsJson: b.signalsJson ?? null,
        powTiming: b.powTiming ?? null,
        ja3Hash,
        action: b.action,
      });
      return json(200, result);
    }

    // POST {base}/token/verify
    if (sub === '/token/verify' && method === 'POST') {
      const b = (req.body ?? {}) as VerifyBody;
      if (!b.token) return json(400, { valid: false, reason: 'missing_token' });
      return json(200, await captcha.verifyToken(b.token, req.ip));
    }

    return json(404, { error: 'not_found' });
  }

  return { captcha, basePath: base, handle };
}

export type CaptchaEndpoints = ReturnType<typeof createCaptchaEndpoints>;
