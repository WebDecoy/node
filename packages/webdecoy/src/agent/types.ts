/**
 * Web Bot Auth verification — public types.
 *
 * A local verifier for the WebDecoy Web Bot Auth profile (RFC 9421 HTTP
 * Message Signatures, tag "web-bot-auth"). It answers one question about an
 * inbound request: is it a *cryptographically verified* AI agent, an
 * *impersonator* forging a known agent's identity, an unverifiable *claim*,
 * or plain traffic carrying no agent signature at all?
 *
 * The verdict taxonomy mirrors the server-side verifier in the ingest service
 * (WebDecoy/app#320) so the SDK, the edge validator, and the backend all speak
 * the same language.
 */

/** The four possible outcomes of Web Bot Auth verification. */
export type AgentStatus =
  /** No Web Bot Auth signature on the request. Ordinary traffic. */
  | 'none'
  /** Signature verified against a curated agent's published key. Trustworthy. */
  | 'verified'
  /**
   * A signature claiming a **known** agent's key that did **not** verify (bad
   * signature, or outside its created/expires window). A forgery attempt —
   * deny-able, tripwire-grade.
   */
  | 'impersonation'
  /**
   * A signature is present but cannot be verified against any curated agent
   * (unknown keyid, or an unsupported / malformed signature). An unverifiable
   * claim — not proof of an agent, not proof of a forgery.
   */
  | 'claimed';

/**
 * Category an agent falls into, used for allow/deny policy. Matches the
 * category taxonomy used by the edge validator and backend curation.
 */
export type AgentCategory = 'ai_crawlers' | 'search_engines' | 'monitoring' | string;

/** The result of verifying one request. */
export interface AgentVerdict {
  /** Verification outcome. */
  status: AgentStatus;
  /** Human display name of the matched agent (e.g. "OpenAI"). Only on `verified`. */
  agentName?: string;
  /** Category of the matched agent. Only on `verified`. */
  category?: AgentCategory;
  /** The JWK thumbprint keyid the signature claimed. Present on verified/impersonation/claimed. */
  keyId?: string;
  /** Signature algorithm used (e.g. "ed25519", "rsa-pss-sha512"). Only on `verified`. */
  algorithm?: string;
  /**
   * How the verdict was reached — always `'signature'` for now (Web Bot Auth
   * cryptographic verification). Kept for parity with the ingest verifier,
   * which also reports `ip_rdns` / `claimed` methods it derives from other
   * signals unavailable in-process.
   */
  method?: 'signature';
  /** Short, non-sensitive reason string for non-verified outcomes (diagnostics). */
  reason?: string;
}

/** A curated, trusted signing agent whose directory the SDK will fetch. */
export interface SignedAgentDirectory {
  /** Display name, e.g. "OpenAI". */
  name: string;
  /** Category for allow/deny policy. */
  category: AgentCategory;
  /**
   * Origin (scheme + host) whose well-known HTTP Message Signatures directory
   * publishes the agent's keys, e.g. `https://operator.openai.com`. The
   * `/.well-known/http-message-signatures-directory` path is appended
   * automatically. A full URL ending in a path is also accepted verbatim.
   */
  directory: string;
}

/** Options for {@link createAgentVerifier}. */
export interface AgentVerifierOptions {
  /**
   * Trusted agent directories to verify against. Defaults to
   * {@link DEFAULT_SIGNED_AGENT_DIRECTORIES}. Only origins in this list are
   * ever fetched — the request's own `Signature-Agent` header is never used to
   * choose a fetch target, so there is no SSRF surface.
   */
  directories?: SignedAgentDirectory[];
  /**
   * How long a fetched directory stays fresh, in milliseconds. After this the
   * cached keys are still served (stale-while-revalidate) while a background
   * refresh runs, so the warm path never blocks on the network.
   * @default 21600000 (6 hours)
   */
  cacheTtlMs?: number;
  /**
   * Per-directory fetch timeout in milliseconds.
   * @default 5000
   */
  fetchTimeoutMs?: number;
  /**
   * Clock-skew tolerance in seconds applied to a signature's created/expires
   * window.
   * @default 300 (5 minutes)
   */
  toleranceSec?: number;
  /** Emit debug logging to the console. @default false */
  debug?: boolean;
  /**
   * Injectable fetch, primarily for tests. Defaults to the global `fetch`.
   */
  fetchImpl?: typeof fetch;
}

/**
 * A request to verify. Either a WHATWG {@link Request} (the natural shape on
 * Vercel Edge / Next.js middleware and Cloudflare Workers) or a plain object
 * carrying the method, absolute URL, and headers.
 */
export type AgentRequestInput =
  | Request
  | {
      method: string;
      /** Absolute request URL, e.g. `https://example.com/path?q=1`. */
      url: string;
      /** Headers as a WHATWG `Headers` or a plain (lowercased-key) record. */
      headers: Headers | Record<string, string>;
    };
