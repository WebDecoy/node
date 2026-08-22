/**
 * What the SDK considers "the same caller".
 *
 * WHY THIS MODULE EXISTS
 *
 * `rateLimit({ keyBy })` was the only place a caller could change what a rule
 * keyed on, and it was per-rule. Everything else — the decision cache, and any
 * future keyed rule — was IP-only.
 *
 * That is the wrong subject for exactly the traffic worth limiting. On an
 * authenticated API the meaningful caller is a user id or an API key, not an
 * address shared by a whole office or rotated through a proxy pool. It is also
 * the wrong subject for us specifically: the actor model exists because IP is
 * not identity.
 */

import type { RuleContext } from './rules/types';

/**
 * One component of the key that identifies a caller.
 *
 * A string names a field of the request; a function derives whatever you like
 * from the context (a decoded JWT subject, a tenant id, an API key header).
 */
export type Characteristic =
  | 'ip'
  | 'path'
  | 'method'
  | 'userAgent'
  | ((context: RuleContext) => string | undefined);

/** The default: one bucket per client address. */
export const DEFAULT_CHARACTERISTICS: readonly Characteristic[] = ['ip'];

function resolveOne(context: RuleContext, c: Characteristic): string | undefined {
  if (typeof c === 'function') {
    try {
      return c(context) || undefined;
    } catch {
      // A characteristic that throws is a bug in the caller's code, but it must
      // not take the request down. Treat it as absent and fall back below.
      return undefined;
    }
  }
  switch (c) {
    case 'ip':
      return context.ip || undefined;
    case 'path':
      return context.path || undefined;
    case 'method':
      return context.method || undefined;
    case 'userAgent':
      return context.userAgent || undefined;
  }
}

/**
 * Derive the key identifying this caller.
 *
 * If any characteristic is absent the whole key falls back to the IP. The
 * alternative — a key with an empty component — silently merges every request
 * missing that field into one bucket, so an unauthenticated request would share
 * a rate limit with every other unauthenticated request. That is the failure
 * mode where a limit meant for one tenant takes out anonymous traffic site-wide,
 * and it is invisible until it happens.
 */
export function deriveKey(
  context: RuleContext,
  characteristics: readonly Characteristic[] = DEFAULT_CHARACTERISTICS,
): string {
  if (characteristics.length === 0) return context.ip;

  const parts: string[] = [];
  for (const c of characteristics) {
    const value = resolveOne(context, c);
    if (value === undefined) return context.ip;
    parts.push(value);
  }
  return parts.join('|');
}
