/**
 * Web Decoy SDK Types
 * Based on the ingest service API contract
 */

/**
 * Configuration options for the Web Decoy SDK
 */
export interface WebDecoyConfig {
  /**
   * API key for authentication (sk_live_xxxxx format)
   * Get this from your Web Decoy dashboard
   */
  apiKey: string;

  /**
   * API URL for the Web Decoy ingest service
   * @default 'https://api.webdecoy.com'
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
 * Result of the protect() method
 */
export interface ProtectResult {
  /** Whether to allow the request */
  allowed: boolean;

  /** Detection response from the service */
  detection: SDKDetectionResponse;

  /** Error message if the request failed */
  error?: string;
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
