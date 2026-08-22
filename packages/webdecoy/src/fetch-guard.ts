/**
 * One adapter, for every runtime that speaks `Request` and `Response`.
 *
 * WHY THIS EXISTS
 *
 * Express, Fastify and Next.js each grew their own copy of the same middleware:
 * skip-path matching, monitor-versus-enforce, honeytoken arming, the 429 with a
 * `Retry-After`, fail-open error handling. Three copies of a decision tree is
 * three places for the branch that matters to be subtly different — and it
 * already had been, which is how the leftmost-`X-Forwarded-For` bug survived in
 * two adapters after the WordPress plugin fixed it.
 *
 * It is also the answer to "which framework do you support?". Hono, Bun, Deno,
 * Astro, Nitro, SvelteKit and Remix all hand you a WHATWG `Request` and want a
 * `Response` back. Written once here, each of those is a translation layer thin
 * enough not to need a package — see the README recipe — and `@webdecoy/hono` is
 * the one that does, because Hono has a middleware contract worth fitting.
 *
 * No `node:` imports: this is the code path that has to run on Workers.
 */

import { WebDecoy } from './sdk';
import type { WebDecoyConfig, RequestMetadata, ProtectOptions } from './types';
import type { Decision } from './decision';
import { resolveClientIp, normalizeIp } from './client-ip';
import type { TrustedProxies } from './client-ip';
import {
  siteHoneytoken,
  injectHoneytokenLink,
  isInjectableHtml,
  tripwire,
  type SiteHoneytoken,
} from './rules';

export interface FetchGuardOptions extends WebDecoyConfig, ProtectOptions {
  /**
   * Whether a blocking verdict actually blocks. Defaults to `'monitor'`.
   *
   * Nobody adopts a defence by having it break their site on the first install.
   * Watch what it would have done, then switch.
   */
  mode?: 'monitor' | 'enforce';

  /** Paths to skip entirely — health checks, static assets. */
  skipPaths?: (string | RegExp)[];

  /**
   * How much of the `X-Forwarded-For` chain to believe. Defaults to `1` trusted
   * hop: a fetch handler has no socket to fall back on, so there is no
   * believe-nothing default available. See `resolveClientIp`.
   */
  trustProxy?: TrustedProxies;

  /** Override IP resolution entirely. */
  getIP?: (request: Request) => string;

  /**
   * Inject a hidden honeytoken link into HTML responses, and arm the tripwire it
   * points at. Defaults to on when an `apiKey` is present.
   */
  honeytoken?: boolean;

  /** Build the blocking response. Defaults to 403, or 429 for a throttle. */
  onBlocked?: (request: Request, decision: Decision) => Response | Promise<Response>;
}

export interface GuardOutcome {
  /** What the SDK concluded. Always present, in both modes. */
  decision: Decision;
  /**
   * The response to return instead of calling the handler, or undefined to
   * carry on. Undefined in monitor mode even when the decision is a denial.
   */
  response?: Response;
}

export interface FetchGuard {
  /** Evaluate one request. */
  check(request: Request, peer?: string): Promise<GuardOutcome>;
  /**
   * Rewrite an HTML response to carry the honeytoken link. Returns the response
   * unchanged when there is no token yet, or the body is not injectable HTML.
   */
  decorate(response: Response): Promise<Response>;
  /** Whether this path is skipped. */
  skips(pathname: string): boolean;
  /** The underlying SDK, for `detectBot()` and friends. */
  sdk: WebDecoy;
}

function defaultBlocked(_request: Request, decision: Decision): Response {
  const throttled = decision.ruleResult?.action === 'THROTTLE';
  const retryAfter = Number(decision.ruleResult?.metadata?.retryAfter ?? 60);

  if (throttled) {
    return new Response(
      JSON.stringify({
        error: 'Too Many Requests',
        message: decision.reason ?? 'Rate limit exceeded',
        retry_after: retryAfter,
        detection_id: decision.id,
      }),
      {
        status: 429,
        headers: {
          'content-type': 'application/json',
          'retry-after': String(retryAfter),
        },
      },
    );
  }

  return new Response(
    JSON.stringify({
      error: 'Forbidden',
      message: 'Access denied by Web Decoy protection',
      detection_id: decision.id,
    }),
    { status: 403, headers: { 'content-type': 'application/json' } },
  );
}

function matches(pathname: string, patterns: (string | RegExp)[] | undefined): boolean {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((p) =>
    typeof p === 'string' ? pathname === p || pathname.startsWith(p) : p.test(pathname),
  );
}

function headerRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * A guard over WHATWG `Request`/`Response`.
 *
 * ```ts
 * const guard = createFetchGuard({ rules: [tripwire()] });
 *
 * export default {
 *   async fetch(request) {
 *     const { response } = await guard.check(request);
 *     if (response) return response;
 *     return guard.decorate(await handle(request));
 *   },
 * };
 * ```
 */
export function createFetchGuard(options: FetchGuardOptions = {}): FetchGuard {
  const sdk = new WebDecoy(options);
  const mode = options.mode ?? 'monitor';
  const onBlocked = options.onBlocked ?? defaultBlocked;

  // Derived from the API key so every replica computes the same path without
  // coordinating — a random per-process token would advertise a link whose
  // tripwire only one replica had armed. Requests served before the async HMAC
  // settles simply carry no link.
  let token: SiteHoneytoken | null = null;
  if ((options.honeytoken ?? true) && options.apiKey) {
    void siteHoneytoken({ secret: options.apiKey })
      .then((t) => {
        token = t;
        // Arm the path before advertising it: a link with no trap behind it is
        // bait a crawler follows for nothing.
        sdk.addRule(tripwire({ paths: t.activePaths, includeDefaults: false }));
      })
      .catch(() => {
        // Deriving the token is not worth a failed boot.
      });
  }

  function resolveIP(request: Request, peer?: string): string {
    if (options.getIP) return options.getIP(request);
    return (
      resolveClientIp({
        headers: request.headers,
        peer,
        trustProxy: options.trustProxy ?? 1,
      }) ??
      normalizeIp(peer) ??
      '127.0.0.1'
    );
  }

  return {
    sdk,

    skips(pathname: string): boolean {
      return matches(pathname, options.skipPaths);
    },

    async check(request: Request, peer?: string): Promise<GuardOutcome> {
      const url = new URL(request.url);

      const metadata: RequestMetadata = {
        method: request.method,
        path: url.pathname,
        ip: resolveIP(request, peer),
        user_agent: request.headers.get('user-agent') ?? undefined,
        headers: headerRecord(request.headers),
        query: url.search ? url.search.slice(1) : undefined,
        timestamp: Date.now(),
      };

      const decision = await sdk.protect(metadata, {
        threshold: options.threshold,
        skipLocalAnalysis: options.skipLocalAnalysis,
        metadata: options.metadata,
      });

      // Monitor mode records the verdict and serves the request anyway. The
      // decision is still returned, so an application can log or meter it.
      if (decision.allowed || mode !== 'enforce') return { decision };

      return { decision, response: await onBlocked(request, decision) };
    },

    async decorate(response: Response): Promise<Response> {
      const current = token;
      if (!current) return response;
      if (!isInjectableHtml(response.headers.get('content-type'))) return response;
      // A body already consumed by the application cannot be read again, and
      // throwing here would turn a missed detection into a broken page.
      if (response.bodyUsed) return response;

      try {
        const html = await response.text();
        const injected = injectHoneytokenLink(html, current.linkHtml);
        if (injected === html) return new Response(html, response);

        const headers = new Headers(response.headers);
        // Recomputed, or the client truncates the body at the old length.
        headers.delete('content-length');
        return new Response(injected, {
          status: response.status,
          statusText: response.statusText,
          headers,
        });
      } catch {
        return response;
      }
    },
  };
}
