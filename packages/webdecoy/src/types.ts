/**
 * Web Decoy SDK Types
 * Based on the ingest service API contract
 */

import type { Rule } from './rules/types';
import type { AgentVerifierOptions } from './agent/types';
import type { Characteristic } from './characteristics';
import type { DecisionCacheOptions } from './decision-cache';
import type { Logger } from './logger';
import type { Tracer } from './tracing';

export type { ProtectResult, Conclusion, RuleState, RuleOutcome } from './decision';

/**
 * Configuration options for the Web Decoy SDK
 */
export interface WebDecoyConfig {
  /**
   * API key for authentication (sk_live_xxxxx format)
   * Get this from your Web Decoy dashboard
   * Optional — when omitted, SDK runs in local-only mode (rules still evaluate)
   */
  apiKey?: string;

  /**
   * API URL for the Web Decoy ingest service
   * @default 'https://ingest.webdecoy.com'
   */
  apiUrl?: string;

  /**
   * Enable TLS fingerprinting for advanced bot detection
   * @default true
   */
  enableTLSFingerprinting?: boolean;

  /**
   * Threat score threshold for blocking (0-100)
   * Requests with scores above this will be blocked
   * @default 80
   */
  threatScoreThreshold?: number;

  /**
   * Timeout for API requests in milliseconds
   * @default 5000
   */
  timeout?: number;

  /**
   * Enable debug logging
   * @default false
   */
  debug?: boolean;

  /**
   * Whether to reject unauthorized TLS certificates
   * Set to false for development/testing with self-signed certificates
   * @default true
   */
  tlsRejectUnauthorized?: boolean;

  /**
   * Rules to evaluate before calling the detection API
   * Rules are evaluated in order; first DENY/THROTTLE wins
   */
  rules?: Rule[];

  /**
   * Options for local Web Bot Auth agent verification (used by `detectBot()`
   * and the `webBotAuth()` rule) — trusted directories, cache TTL, etc.
   * Defaults are sensible; override only to curate your own agent allowlist.
   */
  webBotAuth?: AgentVerifierOptions;

  /**
   * What counts as "the same caller" — the components of the key that keyed
   * rules and the decision cache use.
   *
   * Defaults to `['ip']`. On an authenticated API the meaningful subject is
   * usually not an address:
   *
   * ```ts
   * characteristics: [(ctx) => ctx.headers['x-api-key']]
   * ```
   *
   * A rule's own `keyBy` still wins over this. If a characteristic is absent on
   * a request the key falls back to the IP rather than bucketing every such
   * request together.
   */
  characteristics?: Characteristic[];

  /**
   * Reuse of decisions that cost a network round trip. `false` disables it.
   *
   * Only server-derived DENY and CHALLENGE verdicts are cached — never ALLOW,
   * and never a rule outcome, because a rate limiter has to see every request.
   * @default { ttl: 60_000, max: 10_000 }
   */
  decisionCache?: DecisionCacheOptions | false;

  /**
   * Where the SDK's diagnostics go. Defaults to `console`, gated on `debug` for
   * everything below `warn`.
   *
   * Any object with `debug`/`info`/`warn`/`error` taking `(message, fields?)`
   * works. For a pino-style logger, whose argument order is the other way
   * round, wrap it with `fromPino()` — passing one directly type-checks and then
   * silently drops every structured field.
   */
  logger?: Logger;

  /**
   * An OpenTelemetry tracer, if you run one.
   *
   * Injected rather than imported so this package stays dependency-free and
   * edge-safe. The interface is a structural subset of OpenTelemetry's, so
   * `trace.getTracer('webdecoy')` works directly:
   *
   * ```ts
   * new WebDecoy({ tracer: trace.getTracer('webdecoy') });
   * ```
   *
   * Omit it and there are no spans, no dependency and no behaviour change.
   */
  tracer?: Tracer;
}

/**
 * TLS connection information from the request
 */
export interface TLSInfo {
  /** TLS version (e.g., 771 for TLS 1.2, 772 for TLS 1.3) */
  version?: number;

  /** List of cipher suites supported by the client */
  cipher_suites?: number[];

  /** List of TLS extensions */
  extensions?: number[];

  /** Elliptic curves supported */
  supported_groups?: number[];

  /** EC point formats */
  ec_point_formats?: number[];

  /** Signature algorithms */
  signature_algorithms?: number[];

  /** Server name indication */
  server_name?: string;

  /** ALPN protocols */
  alpn_protocols?: string[];
}

/**
 * Request metadata sent to the detection service
 */
export interface RequestMetadata {
  /** HTTP method (GET, POST, etc.) */
  method: string;

  /** Request path */
  path: string;

  /** Client IP address (REQUIRED) */
  ip: string;

  /** User-Agent header */
  user_agent?: string;

  /** All request headers */
  headers: Record<string, string>;

  /**
   * Raw query string, without the leading `?`. Populated by the adapters.
   * Read by `attackSignatures()`, which cannot see it via `path` — Express's
   * `req.path` excludes the query, and that is where injection payloads live.
   */
  query?: string;

  /**
   * Request body as text, when the application chooses to supply it. Never
   * populated automatically: buffering a body the application has not already
   * parsed would change its streaming behaviour.
   */
  body?: string;

  /** TLS connection information */
  tls_info?: TLSInfo;

  /** Request timestamp (Unix milliseconds) */
  timestamp: number;
}

/**
 * Local analysis performed by the SDK
 */
export interface LocalAnalysis {
  /** True if suspicious headers detected */
  suspicious_headers: boolean;

  /** True if Sec-CH-UA header is missing */
  missing_sec_ch_ua: boolean;

  /** True if IP is from a known datacenter */
  datacenter_ip: boolean;

  /** Local threat score (0-100) */
  local_score: number;

  /** True if server-side verification is needed */
  needs_verification: boolean;

  /** Detection flags */
  flags: string[];
}

/**
 * Detection request sent to the ingest service
 */
export interface SDKDetectionRequest {
  request_metadata: RequestMetadata;
  local_analysis: LocalAnalysis;
}

/**
 * Detection response from the ingest service
 */
export interface SDKDetectionResponse {
  /** Decision: "allow", "block", or "challenge" */
  decision: 'allow' | 'block' | 'challenge';

  /** Confidence score (0-100) */
  confidence: number;

  /** Threat level classification */
  threat_level: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** True if a bot was detected */
  bot_detected: boolean;

  /** Type of bot detected (if any) */
  bot_type?: string;

  /** Unique detection ID */
  detection_id: string;

  /** True if a response rule was enforced */
  rule_enforced: boolean;
}

/**
 * Options for the protect() method
 */
export interface ProtectOptions {
  /** Custom threat score threshold for this request */
  threshold?: number;

  /** Skip local analysis and only use server-side detection */
  skipLocalAnalysis?: boolean;

  /** Additional metadata to include in the detection */
  metadata?: Record<string, any>;
}
