/**
 * The request headers a detection report may carry.
 *
 * A credential header belongs to your visitor: their session cookie, their
 * bearer token, an API key. WebDecoy never needs its value to score a request,
 * so the value never leaves your server. The name is still sent, because a
 * client that guesses an admin secret is itself evidence.
 *
 * Only the outgoing report is redacted. Rules and characteristics run on the
 * full request before this, so a rate-limit key derived from `x-api-key` works
 * exactly as before.
 */

/**
 * Header names whose values are credentials. A substring pattern rather than a
 * list, so names nobody listed (`x-hasura-admin-secret`, `x-vault-token`) are
 * caught too. WebDecoy's ingest service enforces the same pattern on its side,
 * so an SDK that predates this file is covered as well.
 */
export const CREDENTIAL_HEADER =
  /cookie|auth|token|secret|passw|session|credential|csrf|xsrf|api[-_]?key|access[-_]?key|private[-_]?key/i;

/**
 * WebDecoy's own clearance cookie. It is issued by WebDecoy, carries no
 * credential for your site, and is how a cleared client is recognised across
 * requests, so it is the one cookie a report keeps.
 */
const CLEARANCE_COOKIE = 'wd_clearance';

/** `headers` with every credential value removed. Names are kept. */
export function reportableHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!CREDENTIAL_HEADER.test(name)) {
      out[name] = value;
      continue;
    }
    out[name] = name.toLowerCase() === 'cookie' ? clearanceCookieOnly(value) : '';
  }
  return out;
}

function clearanceCookieOnly(cookie: string): string {
  return String(cookie ?? '')
    .split(';')
    .map((pair) => pair.trim())
    .filter((pair) => pair.slice(0, pair.indexOf('=')).trim() === CLEARANCE_COOKIE)
    .join('; ');
}
