/**
 * The parts of a middleware that are the same in every framework.
 *
 * WHY THIS EXISTS
 *
 * Express, Fastify, Next.js and the fetch guard each grew their own copy of the
 * same decision tree: skip-path matching, monitor-versus-enforce, honeytoken
 * arming, the 429 payload, the 403 payload. Four copies of one set of rules.
 *
 * That is not a tidiness complaint. The leftmost-`X-Forwarded-For` bug survived
 * in two adapters after the same class of bug had already been fixed elsewhere,
 * precisely because there was no one place to fix. Every copy is a place the
 * next correction can fail to land, and each one reads perfectly sensibly on its
 * own — which is why review does not catch it.
 *
 * WHAT STAYS IN THE ADAPTERS
 *
 * Everything that touches the framework: reading metadata off its request
 * object, writing its response, and injecting the honeytoken link into whatever
 * that framework calls a body. Response mechanics differ genuinely — Express
 * intercepts `res.write`/`res.end`, Fastify uses an `onSend` hook, a fetch
 * handler rebuilds a `Response` — and the detail in each is hard-won. This
 * module holds the decisions, not the I/O.
 */

import type { ProtectResult } from './decision';
import type { WebDecoy } from './sdk';
import { siteHoneytoken, tripwire, type SiteHoneytoken } from './rules';

/** Whether a request path is exempt from protection. */
export function shouldSkipPath(
  path: string,
  patterns: readonly (string | RegExp)[] | undefined,
): boolean {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((pattern) =>
    typeof pattern === 'string'
      ? path === pattern || path.startsWith(pattern)
      : pattern.test(path),
  );
}

/** A framework-agnostic description of the response a blocked request gets. */
export interface BlockResponse {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/**
 * What to answer a request the rules refused.
 *
 * Returns null when the decision was not a rule refusal — a server-score block
 * has no rule to name, and each adapter's `onBlocked` handles that case with its
 * own default.
 */
export function ruleBlockResponse(decision: ProtectResult): BlockResponse | null {
  const rr = decision.ruleResult;
  if (decision.allowed || !rr) return null;

  if (rr.action === 'THROTTLE') {
    // Retry-After is not decoration: without it a client backs off by guessing,
    // and the guess is usually "immediately".
    const retryAfter = Number(rr.metadata?.retryAfter ?? 60);
    return {
      status: 429,
      headers: { 'Retry-After': String(retryAfter) },
      body: {
        error: 'Too Many Requests',
        message: rr.reason || 'Rate limit exceeded',
        retry_after: retryAfter,
      },
    };
  }

  if (rr.action === 'DENY') {
    return {
      status: 403,
      headers: {},
      body: {
        error: 'Forbidden',
        message: rr.reason || 'Access denied by rule',
        rule: rr.rule,
      },
    };
  }

  return null;
}

export interface HoneytokenArmingOptions {
  /** The site honeytoken is derived from this. No key, no token. */
  apiKey?: string;
  /** Defaults to on when an apiKey is present. */
  enabled?: boolean;
  /** Reported when derivation fails, so a silent absence is at least loggable. */
  onError?: (error: unknown) => void;
}

/**
 * Derive the site honeytoken and arm the tripwire it points at.
 *
 * Returns a getter rather than a promise: derivation is async (WebCrypto HMAC,
 * so this still runs on edge runtimes) and requests served before it settles
 * simply carry no link. That is a few milliseconds at boot against the
 * alternative of blocking startup on crypto.
 *
 * The token is derived from the API key so every replica computes the same path
 * without coordinating. A random per-process token would advertise a link whose
 * tripwire only one replica had armed — bait with no trap behind it.
 */
export function armSiteHoneytoken(
  sdk: WebDecoy,
  options: HoneytokenArmingOptions,
): () => SiteHoneytoken | null {
  let token: SiteHoneytoken | null = null;

  void deriveAndArm(sdk, options).then((t) => {
    token = t;
  });

  return () => token;
}

/**
 * Derive and arm, awaited.
 *
 * For a framework whose registration is already an async boot phase — Fastify's
 * plugin hook — where waiting costs nothing and removes the window in which
 * early requests are served without the link. Same logic as
 * {@link armSiteHoneytoken}; only the timing differs, which is why it is a
 * second entry point rather than a second implementation.
 */
export async function deriveAndArm(
  sdk: WebDecoy,
  options: HoneytokenArmingOptions,
): Promise<SiteHoneytoken | null> {
  const enabled = (options.enabled ?? true) && Boolean(options.apiKey);
  if (!enabled) return null;

  try {
    const token = await siteHoneytoken({ secret: options.apiKey as string });
    // Arm the path before advertising it. Without this the link is bait with
    // no trap: a crawler follows it and nothing happens.
    sdk.addRule(tripwire({ paths: token.activePaths, includeDefaults: false }));
    return token;
  } catch (error) {
    // Deriving the token is not worth a failed boot. No token, no injection.
    options.onError?.(error);
    return null;
  }
}
