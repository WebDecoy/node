/**
 * AgentVerifier — the public entry point for local Web Bot Auth verification.
 *
 * Wraps the cached directory client and the signature core into a single
 * `verify(request)` call returning an {@link AgentVerdict}. Designed for the
 * hot path of edge/Node middleware: warm verification is a header parse, one
 * map lookup, and one WebCrypto verify — no network, well under the 5ms p95
 * budget in the acceptance criteria.
 */

import { DirectoryCache, DEFAULT_SIGNED_AGENT_DIRECTORIES } from './directory';
import { verifyWebBotAuth, type NormalizedRequest } from './signature';
import type { AgentRequestInput, AgentVerdict, AgentVerifierOptions } from './types';

const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000;
const DEFAULT_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_TOLERANCE_SEC = 300;

export class AgentVerifier {
  private readonly cache: DirectoryCache;
  private readonly toleranceSec: number;

  constructor(options: AgentVerifierOptions = {}) {
    this.toleranceSec = options.toleranceSec ?? DEFAULT_TOLERANCE_SEC;
    this.cache = new DirectoryCache({
      directories: options.directories ?? DEFAULT_SIGNED_AGENT_DIRECTORIES,
      cacheTtlMs: options.cacheTtlMs ?? DEFAULT_TTL_MS,
      fetchTimeoutMs: options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
      debug: options.debug ?? false,
      fetchImpl: options.fetchImpl ?? fetch,
    });
  }

  /** Pre-fetch trusted directories so the first request verifies warm. */
  warmup(): void {
    this.cache.prime();
  }

  /** Verify a request's Web Bot Auth signature (if any) locally. */
  async verify(request: AgentRequestInput): Promise<AgentVerdict> {
    let req: NormalizedRequest;
    try {
      req = normalize(request);
    } catch {
      // Can't even parse the request shape — treat as ordinary traffic rather
      // than fabricate an agent verdict.
      return { status: 'none' };
    }

    const result = await verifyWebBotAuth(req, this.cache.resolveKey, this.toleranceSec);

    switch (result.outcome) {
      case 'verified':
        return {
          status: 'verified',
          method: 'signature',
          keyId: result.keyId,
          agentName: result.key?.name,
          category: result.key?.category,
          algorithm: result.key?.algorithm,
        };
      case 'impersonation':
        return {
          status: 'impersonation',
          method: 'signature',
          keyId: result.keyId,
          agentName: result.key?.name,
          category: result.key?.category,
          reason: result.reason,
        };
      case 'claimed':
        return { status: 'claimed', keyId: result.keyId, reason: result.reason };
      default:
        return { status: 'none' };
    }
  }

  /** Cached-key count (diagnostics/tests). */
  get cachedKeyCount(): number {
    return this.cache.size;
  }
}

/** Convenience factory mirroring the SDK's other `create*` helpers. */
export function createAgentVerifier(options: AgentVerifierOptions = {}): AgentVerifier {
  return new AgentVerifier(options);
}

/** Normalize a WHATWG Request or a plain shape into `{ method, url, headers }`. */
function normalize(input: AgentRequestInput): NormalizedRequest {
  if (isRequest(input)) {
    return { method: input.method, url: new URL(input.url), headers: input.headers };
  }
  const headers = input.headers instanceof Headers ? input.headers : toHeaders(input.headers);
  return { method: input.method, url: new URL(input.url), headers };
}

function isRequest(input: AgentRequestInput): input is Request {
  return (
    typeof Request !== 'undefined' &&
    input instanceof Request &&
    typeof (input as Request).url === 'string'
  );
}

function toHeaders(record: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(record)) {
    if (v !== undefined && v !== null) h.set(k, String(v));
  }
  return h;
}
