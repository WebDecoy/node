/**
 * Signature-Agent identity (draft-ietf-webbotauth-httpsig-protocol-01 §5.5).
 *
 * A Signature-Agent value is a URL that serves a JWK Set, and that URL (minus
 * its query) is the agent's identity. A bare origin is the form signers sent
 * under earlier drafts and still send today; it means the origin's well-known
 * directory, because fetching the origin itself would return a web page.
 *
 * Mirrors `ResolveSignatureAgent` in github.com/WebDecoy/web-bot-auth. The
 * shared vectors in `signature-agent-resolution.json` keep the two in step.
 */

export const WELL_KNOWN_DIRECTORY = '/.well-known/http-message-signatures-directory';

export interface ResolvedAgent {
  /** The URL a verifier fetches the JWK Set from. */
  fetch: string;
  /** The identity keys are attributed to: the fetched URL without its query. */
  identifier: string;
}

/** Resolve a Signature-Agent value. Throws when it is not a usable https URL. */
export function resolveSignatureAgent(value: string): ResolvedAgent {
  // WHATWG URL parsing forgives "https:///host"; the draft does not.
  if (!/^https:\/\/[^/\\]/i.test(value)) throw new Error('signature-agent must be an https URL');
  const url = new URL(value);
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) {
    throw new Error('signature-agent must be an https URL');
  }
  url.hash = '';
  const hasQuery = url.href.includes('?');
  const authority = canonicalAuthority(url);
  if (url.pathname === '/' && !hasQuery) {
    const wellKnown = `https://${authority}${WELL_KNOWN_DIRECTORY}`;
    return { fetch: wellKnown, identifier: wellKnown };
  }
  const path = url.pathname.replace(/%[0-9a-f]{2}/gi, (m) => m.toUpperCase());
  return { fetch: url.href, identifier: `https://${authority}${path}` };
}

function canonicalAuthority(url: URL): string {
  const host = url.hostname.toLowerCase();
  if (!url.port || url.port === '443') return host;
  return `${host}:${url.port}`;
}
