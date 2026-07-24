/**
 * Web-standard crypto + encoding helpers.
 *
 * Everything here runs on WinterCG-compatible edge runtimes (Vercel Edge
 * Middleware, Cloudflare Workers, Deno, Bun) as well as Node >= 18 — only
 * `globalThis.crypto`, `TextEncoder`/`TextDecoder`, and `atob`/`btoa` are used.
 * The package is bundled into a single file, so a single `node:` import
 * anywhere in the graph would break consumers' Edge builds; keep it out.
 */

const encoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

/** SHA-256 of a UTF-8 string, hex-encoded. */
export async function sha256Hex(data: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return toHex(new Uint8Array(digest));
}

/** HMAC-SHA-256 of a UTF-8 string with a UTF-8 secret, hex-encoded. */
export async function hmacSha256Hex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return toHex(new Uint8Array(sig));
}

/** `bytes` cryptographically-random bytes, hex-encoded. */
export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

/** Constant-time string comparison. */
export function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** UTF-8 string → base64url (unpadded). */
export function base64urlEncode(data: string): string {
  const bytes = encoder.encode(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url → UTF-8 string. Throws on invalid input. */
export function base64urlDecode(data: string): string {
  const b64 = data.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/**
 * FNV-1a 64-bit hash, hex-encoded (16 chars). Non-cryptographic — use only for
 * correlation keys, never for anything an attacker gains by forging.
 */
export function fnv1a64Hex(data: string): string {
  const PRIME = 0x100000001b3n;
  const MASK = 0xffffffffffffffffn;
  let hash = 0xcbf29ce484222325n;
  const bytes = encoder.encode(data);
  for (let i = 0; i < bytes.length; i++) {
    hash ^= BigInt(bytes[i]);
    hash = (hash * PRIME) & MASK;
  }
  return hash.toString(16).padStart(16, '0');
}
