/**
 * Cached Web Bot Auth directory client.
 *
 * Fetches the JWK sets of a **curated** set of trusted agent directories,
 * imports their keys into WebCrypto, and indexes them by JWK-thumbprint keyid
 * so signatures resolve in O(1) with zero network on the warm path.
 *
 * Security posture — the reason this is curated-only:
 * a request's own `Signature-Agent` header is **never** used to choose a fetch
 * target, so an attacker cannot make the middleware fetch an arbitrary URL
 * (no SSRF). Only the origins in {@link AgentVerifierOptions.directories} are
 * ever contacted. This mirrors the backend curation
 * (`backend/internal/services/signed_agents.go`).
 *
 * Freshness — stale-while-revalidate: once populated, an expired cache keeps
 * serving its keys while a background refresh runs, so verification latency is
 * never coupled to a directory fetch. A cold cache (never populated) blocks
 * once to fetch, then backs off briefly if every directory is unreachable so a
 * degraded network can't be hammered per request.
 */

import { jwkThumbprint, type JWK } from './thumbprint';
import type { VerificationKey, KeyResolver } from './signature';
import type { SignedAgentDirectory } from './types';

const WELL_KNOWN = '/.well-known/http-message-signatures-directory';
const COLD_RETRY_BACKOFF_MS = 30_000;

/**
 * The default curated allowlist. These are the agents that sign production
 * traffic today; kept in lock-step with the backend's curated list.
 */
export const DEFAULT_SIGNED_AGENT_DIRECTORIES: SignedAgentDirectory[] = [
  { name: 'OpenAI', category: 'ai_crawlers', directory: 'https://operator.openai.com' },
  { name: 'OpenAI ChatGPT', category: 'ai_crawlers', directory: 'https://chatgpt.com' },
];

interface DirectoryCacheOptions {
  directories: SignedAgentDirectory[];
  cacheTtlMs: number;
  fetchTimeoutMs: number;
  debug: boolean;
  fetchImpl: typeof fetch;
}

export class DirectoryCache {
  private readonly opts: DirectoryCacheOptions;
  private keys = new Map<string, VerificationKey>();
  private refreshedAt = 0;
  private nextColdRetryAt = 0;
  private inflight: Promise<void> | null = null;

  constructor(opts: DirectoryCacheOptions) {
    this.opts = opts;
  }

  /** Resolve a keyid to a verification key, fetching/refreshing as needed. */
  resolveKey: KeyResolver = async (keyId: string) => {
    await this.ensureFresh();
    return this.keys.get(keyId);
  };

  /** Kick off a fetch without blocking — call at startup to warm the cache. */
  prime(): void {
    if (this.keys.size === 0 && Date.now() >= this.nextColdRetryAt) void this.refresh();
  }

  /** Number of keys currently cached (diagnostics/tests). */
  get size(): number {
    return this.keys.size;
  }

  private async ensureFresh(): Promise<void> {
    const now = Date.now();
    const stale = now - this.refreshedAt > this.opts.cacheTtlMs;
    if (this.keys.size > 0) {
      if (stale) void this.refresh(); // serve stale, revalidate in the background
      return;
    }
    // Cold: block once to populate, unless we're backing off a recent failure.
    if (now < this.nextColdRetryAt) return;
    await this.refresh();
  }

  /** Re-fetch every directory. De-duplicated: concurrent callers share one run. */
  refresh(): Promise<void> {
    if (this.inflight) return this.inflight;
    this.inflight = this.doRefresh().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async doRefresh(): Promise<void> {
    const results = await Promise.all(
      this.opts.directories.map((src) => this.fetchDirectory(src)),
    );

    // Start from last-known-good so one flaky directory can't drop live keys.
    const next = new Map(this.keys);
    let fetchedAny = false;
    for (const keys of results) {
      if (keys === null) continue;
      fetchedAny = true;
      for (const k of keys) next.set(k.thumbprint, k.key);
    }

    if (fetchedAny) {
      this.keys = next;
      this.refreshedAt = Date.now();
      this.nextColdRetryAt = 0;
      this.debug(`refreshed: ${this.keys.size} key(s) across ${this.opts.directories.length} directories`);
    } else if (this.keys.size === 0) {
      // Every directory failed and we still have nothing — back off briefly.
      this.nextColdRetryAt = Date.now() + COLD_RETRY_BACKOFF_MS;
      this.debug('all directories unreachable; backing off cold retry');
    }
  }

  private async fetchDirectory(
    src: SignedAgentDirectory,
  ): Promise<{ thumbprint: string; key: VerificationKey }[] | null> {
    const url = directoryUrl(src.directory);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.fetchTimeoutMs);
    try {
      const res = await this.opts.fetchImpl(url, {
        signal: controller.signal,
        headers: {
          Accept:
            'application/http-message-signatures-directory+json, application/jwk-set+json, application/json',
        },
        redirect: 'follow',
      });
      if (!res.ok) {
        this.debug(`${src.name}: HTTP ${res.status}`);
        return null;
      }
      const body = (await res.json()) as { keys?: JWK[] };
      if (!body || !Array.isArray(body.keys)) {
        this.debug(`${src.name}: no keys in directory`);
        return null;
      }
      const out: { thumbprint: string; key: VerificationKey }[] = [];
      for (const jwk of body.keys) {
        const resolved = await importKey(jwk, src);
        if (resolved) out.push(resolved);
      }
      this.debug(`${src.name}: ${out.length} key(s)`);
      return out;
    } catch (err) {
      this.debug(`${src.name}: fetch failed — ${(err as Error).message}`);
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  private debug(msg: string): void {
    if (this.opts.debug) console.log(`[WebDecoy][web-bot-auth] ${msg}`);
  }
}

/** Append the well-known path unless the directory string already carries one. */
function directoryUrl(directory: string): string {
  const u = new URL(directory);
  if (u.pathname && u.pathname !== '/') return u.toString();
  u.pathname = WELL_KNOWN;
  return u.toString();
}

/**
 * Import a directory JWK into a verification key. Unsupported or malformed
 * keys are skipped (a directory may legitimately publish key types outside
 * this profile).
 */
async function importKey(
  jwk: JWK,
  src: SignedAgentDirectory,
): Promise<{ thumbprint: string; key: VerificationKey } | null> {
  try {
    let cryptoKey: CryptoKey;
    let verifyParams: AlgorithmIdentifier | RsaPssParams;
    let algorithm: string;

    if (jwk.kty === 'OKP') {
      if (jwk.crv !== 'Ed25519' || !jwk.x) return null;
      cryptoKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
        { name: 'Ed25519' },
        false,
        ['verify'],
      );
      verifyParams = { name: 'Ed25519' };
      algorithm = 'ed25519';
    } else if (jwk.kty === 'RSA') {
      if (!jwk.n || !jwk.e) return null;
      cryptoKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', n: jwk.n, e: jwk.e },
        { name: 'RSA-PSS', hash: 'SHA-512' },
        false,
        ['verify'],
      );
      // RFC 9421 rsa-pss-sha512: salt length equals the hash length (64 bytes).
      verifyParams = { name: 'RSA-PSS', saltLength: 64 };
      algorithm = 'rsa-pss-sha512';
    } else {
      return null;
    }

    const thumbprint = await jwkThumbprint(jwk);
    return {
      thumbprint,
      key: {
        cryptoKey,
        verifyParams,
        algorithm,
        name: src.name,
        category: src.category,
        nbf: normalizeEpoch(jwk.nbf),
        exp: normalizeEpoch(jwk.exp),
      },
    };
  } catch {
    return null;
  }
}

/**
 * Tolerate directory timestamps published in milliseconds — RFC 7517
 * NumericDate is seconds, but live deployments (including Cloudflare Research's
 * example directory) publish `nbf` in milliseconds. Ported from the Go lib's
 * `normalizeEpoch`.
 */
function normalizeEpoch(v: number | undefined): number | undefined {
  if (v === undefined || v === 0) return undefined;
  return v > 1_000_000_000_000 ? Math.floor(v / 1000) : v;
}
