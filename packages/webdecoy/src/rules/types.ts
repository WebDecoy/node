/**
 * Rules Engine Types
 * Core interfaces for the WebDecoy rules engine
 */

/**
 * Context available to rules during evaluation
 */
export interface RuleContext {
  /** Client IP address */
  ip: string;
  /** Request path */
  path: string;
  /** HTTP method */
  method: string;
  /** User-Agent string */
  userAgent?: string;
  /** Request headers (lowercase keys) */
  headers: Record<string, string>;
  /** Request timestamp */
  timestamp: number;
  /** IP enrichment data (populated async when available) */
  enrichment?: IPEnrichmentData;
}

/**
 * Result of evaluating a single rule
 */
export interface RuleResult {
  /** Action to take */
  action: 'ALLOW' | 'DENY' | 'THROTTLE';
  /** Name of the rule that produced this result */
  rule: string;
  /** Human-readable reason */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * A rule that can evaluate request context and produce a decision
 */
export interface Rule {
  /** Unique name for this rule */
  name: string;
  /** Evaluate the rule against request context */
  evaluate(context: RuleContext): RuleResult;
  /** Clean up resources (timers, etc.) */
  destroy?(): void;
}

/**
 * Configuration for rate limiting
 */
export interface RateLimitConfig {
  /** Maximum requests allowed in the window */
  max: number;
  /** Window size in seconds */
  window: number;
  /** Algorithm: 'fixed' (default) or 'sliding' */
  algorithm?: 'fixed' | 'sliding';
  /** Custom key derivation function. Default: by IP */
  keyBy?: (context: RuleContext) => string;
  /** Action when limit is exceeded: 'DENY' or 'THROTTLE' (default: 'THROTTLE') */
  action?: 'DENY' | 'THROTTLE';
  /** Dry run mode: log violations but don't block */
  dryRun?: boolean;
}

/**
 * Configuration for filter rules
 */
export interface FilterConfig {
  /** Filter expression (e.g., 'ip.vpn or ip.tor') */
  expression: string;
  /** Action when filter matches: 'DENY' (default) or 'THROTTLE' */
  action?: 'DENY' | 'THROTTLE';
  /** Dry run mode: log violations but don't block */
  dryRun?: boolean;
}

/**
 * A violation event recorded when a rule triggers
 */
export interface ViolationEvent {
  /** Rule that triggered */
  rule: string;
  /** Action taken */
  action: 'DENY' | 'THROTTLE' | 'ALLOW';
  /** Client IP */
  ip: string;
  /** Request path */
  path?: string;
  /** HTTP method */
  method?: string;
  /** User-Agent */
  userAgent?: string;
  /** Reason for the violation */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, any>;
  /** Whether this was a dry run */
  dryRun: boolean;
  /** When the violation occurred (ISO 8601) */
  timestamp: string;
}

/**
 * IP enrichment data from the WebDecoy API
 */
export interface IPEnrichmentData {
  ip: string;
  security: {
    vpn: boolean;
    proxy: boolean;
    tor: boolean;
    relay: boolean;
    hosting: boolean;
  };
  location: {
    country: string;
    country_name: string;
    city: string;
    timezone: string;
  };
  network: {
    asn: number;
    asn_org: string;
  };
  reputation: {
    abuse_score: number;
    total_reports: number;
    is_high_risk: boolean;
  };
  categories: string[];
}

/**
 * Combined result from evaluating all rules
 */
export interface RuleEngineResult {
  /** Final action (first DENY/THROTTLE wins, or ALLOW) */
  action: 'ALLOW' | 'DENY' | 'THROTTLE';
  /** The rule that caused the action (null if all allowed) */
  rule?: string;
  /** Reason from the deciding rule */
  reason?: string;
  /** Metadata from the deciding rule */
  metadata?: Record<string, any>;
  /** All violations generated during evaluation */
  violations: ViolationEvent[];
}
