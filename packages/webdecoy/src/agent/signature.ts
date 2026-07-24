/**
 * RFC 9421 HTTP Message Signatures — the Web Bot Auth verification core.
 *
 * Verifies signatures tagged `web-bot-auth`: parse `Signature-Input` /
 * `Signature`, rebuild the signature base for each covered-component set, and
 * check the raw signature with WebCrypto against a key resolved by its JWK
 * thumbprint keyid. Adapted from the WebDecoy edge validator
 * (`edge/clearance-worker/src/web-bot-auth.ts`), generalized to resolve keys
 * from a directory cache instead of a pushed key list.
 *
 * Zero dependencies, Edge-runtime safe: only `crypto.subtle`, `TextEncoder`,
 * `atob`, and `URL` are used.
 */

import { parseDictionary, type DictEntry, type BareItem } from './sfv';

const TAG = 'web-bot-auth';
const encoder = new TextEncoder();

/** A verification key resolved from a trusted directory, ready for WebCrypto. */
export interface VerificationKey {
  cryptoKey: CryptoKey;
  /** WebCrypto verify params (e.g. `{ name: 'Ed25519' }`). */
  verifyParams: AlgorithmIdentifier | RsaPssParams;
  /** Human-readable algorithm label, e.g. "ed25519". */
  algorithm: string;
  /** Display name of the owning agent. */
  name: string;
  /** Category of the owning agent. */
  category: string;
  /** Key validity bounds in Unix seconds, if the directory published them. */
  nbf?: number;
  exp?: number;
}

/** Resolves a JWK-thumbprint keyid to a verification key, or undefined if unknown. */
export type KeyResolver = (keyId: string) => Promise<VerificationKey | undefined>;

export type CoreOutcome = 'none' | 'verified' | 'impersonation' | 'claimed';

export interface CoreResult {
  outcome: CoreOutcome;
  keyId?: string;
  key?: VerificationKey;
  reason?: string;
}

/** A normalized request the verifier operates on. */
export interface NormalizedRequest {
  method: string;
  url: URL;
  headers: Headers;
}

interface Component {
  name: string;
  /** sf-dictionary member key, for `"signature-agent";key="…"`. */
  keyParam?: string;
}

interface SigInputMember {
  label: string;
  components: Component[];
  params: Map<string, BareItem>;
  /** Verbatim member text, for the `@signature-params` line. */
  raw: string;
}

/**
 * Verify every `web-bot-auth`-tagged signature on the request. Returns the
 * highest-precedence outcome: verified > impersonation > claimed > none.
 *
 * - **verified**: a signature validated against a resolvable trusted key.
 * - **impersonation**: a signature claimed a **known** key (resolvable) but
 *   failed crypto or fell outside its validity window — a forgery.
 * - **claimed**: a signature is present but its keyid is unknown, or it is
 *   malformed / unsupported — unverifiable, but not proof of forgery.
 * - **none**: no `web-bot-auth` signature at all.
 */
export async function verifyWebBotAuth(
  req: NormalizedRequest,
  resolveKey: KeyResolver,
  toleranceSec: number,
): Promise<CoreResult> {
  const sigInput = req.headers.get('signature-input');
  const sigHeader = req.headers.get('signature');
  if (!sigInput && !sigHeader) return { outcome: 'none' };
  // A half-present signature is a malformed claim, not a confirmed forgery.
  if (!sigInput || !sigHeader) return { outcome: 'claimed', reason: 'incomplete-signature' };

  let members: SigInputMember[];
  let sigs: Map<string, Uint8Array>;
  try {
    members = parseSignatureInput(sigInput);
    sigs = parseSignatureBytes(sigHeader);
  } catch {
    return { outcome: 'claimed', reason: 'malformed-signature' };
  }

  const now = Date.now() / 1000;
  let best: CoreResult = { outcome: 'none' };

  for (const m of members) {
    if (m.params.get('tag') !== TAG) continue;
    // Below this line every path yields at least 'claimed' — a web-bot-auth
    // signature is present. A more specific claimed reason (unknown-key,
    // uncoverable-component) can still replace this generic fallback.
    if (best.outcome === 'none') best = { outcome: 'claimed', reason: 'unverifiable' };

    const sig = sigs.get(m.label);
    if (!sig) continue;

    const keyid = m.params.get('keyid');
    if (typeof keyid !== 'string') continue;

    // Must bind the host, per the profile.
    if (!m.components.some((c) => c.name === '@authority' || c.name === '@target-uri')) continue;

    const key = await resolveKey(keyid);
    if (!key) {
      // Unknown agent — a claim we can't confirm or refute.
      best = higher(best, { outcome: 'claimed', keyId: keyid, reason: 'unknown-key' });
      continue;
    }

    // Known key: from here a failure is impersonation of a real agent.
    const created = numeric(m.params.get('created'));
    const expires = numeric(m.params.get('expires'));
    if (expires !== undefined && now > expires + toleranceSec) {
      best = higher(best, { outcome: 'impersonation', keyId: keyid, key, reason: 'expired' });
      continue;
    }
    if (created !== undefined && now + toleranceSec < created) {
      best = higher(best, { outcome: 'impersonation', keyId: keyid, key, reason: 'not-yet-valid' });
      continue;
    }
    if (key.exp !== undefined && now > key.exp + toleranceSec) {
      best = higher(best, { outcome: 'impersonation', keyId: keyid, key, reason: 'key-expired' });
      continue;
    }
    if (key.nbf !== undefined && now + toleranceSec < key.nbf) {
      best = higher(best, { outcome: 'impersonation', keyId: keyid, key, reason: 'key-not-yet-valid' });
      continue;
    }

    let base: string;
    try {
      base = buildSignatureBase(req, m);
    } catch {
      // A covered component we can't derive — can't confirm the forgery.
      best = higher(best, { outcome: 'claimed', keyId: keyid, reason: 'uncoverable-component' });
      continue;
    }

    let ok = false;
    try {
      ok = await crypto.subtle.verify(
        key.verifyParams,
        key.cryptoKey,
        sig as BufferSource,
        encoder.encode(base),
      );
    } catch {
      ok = false;
    }
    if (ok) {
      return { outcome: 'verified', keyId: keyid, key };
    }
    best = higher(best, { outcome: 'impersonation', keyId: keyid, key, reason: 'bad-signature' });
  }

  return best;
}

const PRECEDENCE: Record<CoreOutcome, number> = { none: 0, claimed: 1, impersonation: 2, verified: 3 };
// `>=` so a later result of equal precedence (a more specific `claimed`
// reason) replaces an earlier generic one; a lower-precedence result never
// downgrades a higher one (impersonation survives a subsequent claim).
function higher(a: CoreResult, b: CoreResult): CoreResult {
  return PRECEDENCE[b.outcome] >= PRECEDENCE[a.outcome] ? b : a;
}

function numeric(v: BareItem | undefined): number | undefined {
  return typeof v === 'number' ? v : undefined;
}

// --- signature base (RFC 9421 §2.5, Web Bot Auth profile subset) ---

function buildSignatureBase(req: NormalizedRequest, m: SigInputMember): string {
  const lines: string[] = [];
  for (const c of m.components) {
    lines.push(`${serializeComponentId(c)}: ${componentValue(req, c)}`);
  }
  lines.push(`"@signature-params": ${m.raw.trim()}`);
  return lines.join('\n');
}

function serializeComponentId(c: Component): string {
  const base = `"${c.name.toLowerCase()}"`;
  return c.keyParam !== undefined ? `${base};key="${c.keyParam}"` : base;
}

function componentValue(req: NormalizedRequest, c: Component): string {
  const name = c.name.toLowerCase();
  switch (name) {
    case '@method':
      return req.method.toUpperCase();
    case '@authority':
      return canonicalAuthority(req.url);
    case '@scheme':
      return req.url.protocol.replace(/:$/, '').toLowerCase();
    case '@target-uri':
      return `${req.url.protocol}//${canonicalAuthority(req.url)}${req.url.pathname}${req.url.search}`;
    case '@path':
      return req.url.pathname;
    case '@query':
      return req.url.search === '' ? '?' : req.url.search;
    case 'signature-agent': {
      const header = req.headers.get('signature-agent');
      if (header === null) throw new Error('signature-agent covered but absent');
      if (c.keyParam !== undefined) return dictMemberValue(header, c.keyParam);
      return header.trim().replace(/\s+/g, ' ');
    }
    default: {
      if (name.startsWith('@')) throw new Error(`unsupported derived component ${name}`);
      const header = req.headers.get(name);
      if (header === null) throw new Error(`covered header ${name} absent`);
      return header.trim().replace(/\s+/g, ' ');
    }
  }
}

function canonicalAuthority(url: URL): string {
  const host = url.hostname.toLowerCase();
  const port = url.port;
  if (!port) return host;
  if ((url.protocol === 'https:' && port === '443') || (url.protocol === 'http:' && port === '80')) {
    return host;
  }
  return `${host}:${port}`;
}

/** Serialize one member of an sf-dictionary header value, per RFC 8941. */
function dictMemberValue(header: string, key: string): string {
  const dict = parseDictionary(header);
  const found = dict.find((d) => d.key === key);
  if (!found) throw new Error(`signature-agent has no member ${key}`);
  return found.raw;
}

// --- header parsing ---

function parseSignatureInput(value: string): SigInputMember[] {
  return parseDictionary(value).map((d: DictEntry) => {
    if (!d.isList) throw new Error(`Signature-Input member ${d.key} is not an inner list`);
    const components: Component[] = d.items.map((it) => {
      if (typeof it.value !== 'string') throw new Error('component identifier is not a string');
      const keyParam = it.params.get('key');
      return { name: it.value, keyParam: typeof keyParam === 'string' ? keyParam : undefined };
    });
    return { label: d.key, components, params: d.params, raw: d.raw };
  });
}

function parseSignatureBytes(value: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const d of parseDictionary(value)) {
    if (d.isList || d.items.length !== 1 || !d.items[0].bytes) {
      throw new Error(`Signature member ${d.key} is not a byte sequence`);
    }
    out.set(d.key, d.items[0].bytes);
  }
  return out;
}
