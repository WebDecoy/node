/**
 * JSON Web Key thumbprints (RFC 7638, plus the OKP variant from RFC 8037
 * Appendix A.3).
 *
 * Web Bot Auth uses the base64url-encoded JWK SHA-256 thumbprint of the
 * signing key as the signature's `keyid`, so a verifier matches directory keys
 * by comparing thumbprints — never by the JWK `kid` field. Ported from the Go
 * `github.com/WebDecoy/web-bot-auth/thumbprint` package so the SDK, edge, and
 * backend derive identical keyids.
 */

export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  n?: string;
  e?: string;
  kid?: string;
  use?: string;
  nbf?: number;
  exp?: number;
}

const encoder = new TextEncoder();

/** RFC 7638 thumbprint of an RSA public JWK. `n`/`e` are base64url as published. */
export async function rsaThumbprint(n: string, e: string): Promise<string> {
  return digest(`{"e":${JSON.stringify(e)},"kty":"RSA","n":${JSON.stringify(n)}}`);
}

/** RFC 8037 A.3 thumbprint of an OKP public JWK (e.g. crv "Ed25519"). */
export async function okpThumbprint(crv: string, x: string): Promise<string> {
  return digest(`{"crv":${JSON.stringify(crv)},"kty":"OKP","x":${JSON.stringify(x)}}`);
}

/**
 * Thumbprint of a JWK. Only the key types Web Bot Auth uses are supported
 * (RSA and OKP); anything else throws.
 */
export async function jwkThumbprint(k: JWK): Promise<string> {
  switch (k.kty) {
    case 'OKP':
      if (!k.crv || !k.x) throw new Error('thumbprint: OKP JWK missing crv or x');
      return okpThumbprint(k.crv, k.x);
    case 'RSA':
      if (!k.n || !k.e) throw new Error('thumbprint: RSA JWK missing n or e');
      return rsaThumbprint(k.n, k.e);
    default:
      throw new Error(`thumbprint: unsupported kty ${JSON.stringify(k.kty)}`);
  }
}

async function digest(canonical: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', encoder.encode(canonical));
  return base64urlBytes(new Uint8Array(buf));
}

/** base64url (unpadded) encoding of raw bytes. */
function base64urlBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
