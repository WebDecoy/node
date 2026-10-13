/**
 * TLS fingerprint matching (JA3/JA4).
 *
 * JA3 is client-supplied and spoofable; JA4 must come from a trusted reverse
 * proxy header. The known-hash lists are intentionally small static pre-filters
 * — comprehensive, frequently-updated matching is delegated to the remote
 * api.webdecoy.com enrichment service.
 */

import type { Detection } from '../types';

export const KNOWN_BOT_JA3_HASHES: Record<string, string> = {
  '3b5074b1b5d032e5620f69f9f700ff0e': 'Python requests',
  b32309a26951912be7dba376398abc3b: 'Python urllib',
  '9e10692f1b7f78228b2d4e424db3a98c': 'Go net/http',
  '473cd7cb9faa642487833865d516e578': 'curl',
  c12f54a3f91dc7bafd92cb59fe009a35: 'Wget',
  '2d1eb5817ece335c24904f516ad5da2f': 'Java HttpClient',
  fc54fe03db02a25e1be5bb5a7678b7a4: 'Node.js axios',
  '579ccef312d18482fc42e2b822ca2430': 'Node.js node-fetch',
  '5d7974c9fe7862e0f9a3eb35a6a5d9c8': 'Puppeteer default',
};

/**
 * Known automation JA4 fingerprints. Ships empty: the SDK has no curated JA4
 * data, so {@link checkJA4Fingerprint} never matches and a JA4 read from
 * `trustedJA4Headers` does not change the score. The platform computes JA4
 * only where it terminates the TLS handshake itself.
 */
export const KNOWN_BOT_JA4_HASHES: Record<string, string> = {};

export function checkJA3Fingerprint(ja3Hash?: string | null): Detection[] {
  if (!ja3Hash) return [];
  const match = KNOWN_BOT_JA3_HASHES[ja3Hash];
  if (match) {
    return [
      {
        category: 'bot',
        score: 0.8,
        confidence: 0.9,
        reason: `TLS fingerprint matches: ${match}`,
      },
    ];
  }
  return [];
}

export function checkJA4Fingerprint(ja4?: string | null): Detection[] {
  if (!ja4) return [];
  const match = KNOWN_BOT_JA4_HASHES[ja4];
  if (match) {
    return [
      {
        category: 'fingerprint',
        score: 0.8,
        confidence: 0.9,
        reason: `TLS JA4 fingerprint matches: ${match}`,
      },
    ];
  }
  return [];
}

/** Read a JA4 fingerprint from the first present trusted proxy header. */
export function readJA4FromHeaders(
  headers: Record<string, string>,
  trustedHeaderNames: string[],
): string | null {
  if (!trustedHeaderNames || trustedHeaderNames.length === 0) return null;
  for (const name of trustedHeaderNames) {
    const v = headers[name];
    if (v && typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}
