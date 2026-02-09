/**
 * Web Decoy SDK
 * Main SDK class for bot detection and protection
 */

import { WebDecoyClient } from './client';
import { analyzeRequest } from './local-analysis';
import { RuleEngine } from './rules/rule-engine';
import { ViolationReporter } from './violation-reporter';
import { IPEnrichmentClient } from './ip-enrichment';
import type { RuleContext, RuleEngineResult, ViolationEvent } from './rules/types';
import {
  WebDecoyConfig,
  RequestMetadata,
  ProtectResult,
  ProtectOptions,
  SDKDetectionRequest,
} from './types';

export class WebDecoy {
  private client: WebDecoyClient | null;
  private config: Omit<Required<WebDecoyConfig>, 'apiKey' | 'rules'> & {
    apiKey?: string;
  };
  private ruleEngine: RuleEngine | null;
  private violationReporter: { report(violations: ViolationEvent[]): void; flush(): Promise<void>; destroy(): Promise<void> } | null = null;
  private ipEnrichmentClient: IPEnrichmentClient | null = null;
  private _hasFilterRules = false;

  constructor(config: WebDecoyConfig) {
    const hasApiKey = !!config.apiKey;

    // Validate API key format if provided
    if (hasApiKey) {
      if (!config.apiKey!.startsWith('sk_live_') && !config.apiKey!.startsWith('sk_test_')) {
        throw new Error(
          'Invalid API key format. API key should start with "sk_live_" or "sk_test_".'
        );
      }
    }

    // Set defaults
    this.config = {
      apiKey: config.apiKey,
      apiUrl: config.apiUrl || 'https://api.webdecoy.com',
      enableTLSFingerprinting: config.enableTLSFingerprinting ?? true,
      threatScoreThreshold: config.threatScoreThreshold ?? 80,
      timeout: config.timeout ?? 5000,
      debug: config.debug ?? false,
      tlsRejectUnauthorized: config.tlsRejectUnauthorized ?? true,
    };

    // Initialize API client only when apiKey is provided
    if (hasApiKey) {
      this.client = new WebDecoyClient({
        apiKey: config.apiKey!,
        apiUrl: this.config.apiUrl,
        timeout: this.config.timeout,
        debug: this.config.debug,
        tlsRejectUnauthorized: this.config.tlsRejectUnauthorized,
      });
    } else {
      this.client = null;
      if (this.config.debug) {
        console.log('[WebDecoy] Running in local-only mode (no API key). Rules will still evaluate.');
      }
    }

    // Initialize rule engine if rules are provided
    if (config.rules && config.rules.length > 0) {
      this.ruleEngine = new RuleEngine(config.rules);
      // Check if any filter rules exist (they need async enrichment)
      this._hasFilterRules = config.rules.some(
        (r) => r.name.startsWith('filter:')
      );
    } else {
      this.ruleEngine = null;
    }

    // Auto-create IP enrichment client when apiKey + filter rules exist
    if (this.client && this._hasFilterRules) {
      this.ipEnrichmentClient = new IPEnrichmentClient(this.client);
    }

    // Auto-create violation reporter when apiKey + rules are both present
    if (this.client && this.ruleEngine) {
      const reporter = new ViolationReporter(this.client, {
        debug: this.config.debug,
      });
      this.setViolationReporter(reporter);
    }

    if (this.config.debug) {
      console.log('[WebDecoy] Initialized with config:', {
        apiUrl: this.config.apiUrl,
        enableTLSFingerprinting: this.config.enableTLSFingerprinting,
        threatScoreThreshold: this.config.threatScoreThreshold,
        hasApiKey,
        rulesCount: config.rules?.length ?? 0,
      });
    }
  }

  /**
   * Evaluate rules against request metadata (synchronous).
   * Returns null if no rules are configured.
   */
  evaluateRules(metadata: RequestMetadata): RuleEngineResult | null {
    if (!this.ruleEngine) return null;

    const context: RuleContext = {
      ip: metadata.ip,
      path: metadata.path,
      method: metadata.method,
      userAgent: metadata.user_agent,
      headers: metadata.headers,
      timestamp: metadata.timestamp || Date.now(),
    };

    const result = this.ruleEngine.evaluate(context);

    // Report violations asynchronously if reporter is attached
    if (result.violations.length > 0 && this.violationReporter) {
      this.violationReporter.report(result.violations);
    }

    return result;
  }

  /**
   * Evaluate rules with async IP enrichment pre-fetch.
   * Use this instead of evaluateRules() when filter rules are present.
   */
  async evaluateRulesAsync(metadata: RequestMetadata): Promise<RuleEngineResult | null> {
    if (!this.ruleEngine) return null;

    const context: RuleContext = {
      ip: metadata.ip,
      path: metadata.path,
      method: metadata.method,
      userAgent: metadata.user_agent,
      headers: metadata.headers,
      timestamp: metadata.timestamp || Date.now(),
    };

    // Pre-fetch IP enrichment if we have filter rules and an enrichment client
    if (this._hasFilterRules && this.ipEnrichmentClient) {
      const enrichment = await this.ipEnrichmentClient.enrich(metadata.ip);
      if (enrichment) {
        context.enrichment = enrichment;
      }
    }

    const result = this.ruleEngine.evaluate(context);

    // Report violations asynchronously if reporter is attached
    if (result.violations.length > 0 && this.violationReporter) {
      this.violationReporter.report(result.violations);
    }

    return result;
  }

  /**
   * Whether this SDK instance has filter rules that need async enrichment
   */
  get hasFilterRules(): boolean {
    return this._hasFilterRules;
  }

  /**
   * Protect a request by checking it against Web Decoy's bot detection
   *
   * @param metadata - Request metadata to analyze
   * @param options - Optional configuration for this specific request
   * @returns Protection result with decision and detection details
   */
  async protect(
    metadata: RequestMetadata,
    options: ProtectOptions = {}
  ): Promise<ProtectResult> {
    try {
      // Validate required fields
      if (!metadata.ip) {
        throw new Error('IP address is required in request metadata');
      }

      // Ensure timestamp is set
      if (!metadata.timestamp) {
        metadata.timestamp = Date.now();
      }

      // Evaluate rules first (if configured)
      // Use async evaluation if filter rules exist (needs IP enrichment)
      const ruleResult = this._hasFilterRules
        ? await this.evaluateRulesAsync(metadata)
        : this.evaluateRules(metadata);

      // If rules denied the request, return immediately without API call
      if (ruleResult && ruleResult.action === 'DENY') {
        return {
          allowed: false,
          detection: {
            decision: 'block',
            confidence: 100,
            threat_level: 'HIGH',
            bot_detected: false,
            detection_id: 'rule_' + Date.now(),
            rule_enforced: true,
          },
          ruleResult,
        };
      }

      // If rules throttled, return a throttle response
      if (ruleResult && ruleResult.action === 'THROTTLE') {
        return {
          allowed: false,
          detection: {
            decision: 'block',
            confidence: 100,
            threat_level: 'MEDIUM',
            bot_detected: false,
            detection_id: 'rule_' + Date.now(),
            rule_enforced: true,
          },
          ruleResult,
        };
      }

      // No API client — return fail-open default
      if (!this.client) {
        return {
          allowed: true,
          detection: {
            decision: 'allow',
            confidence: 0,
            threat_level: 'MINIMAL',
            bot_detected: false,
            detection_id: 'local_' + Date.now(),
            rule_enforced: false,
          },
          ruleResult: ruleResult ?? undefined,
        };
      }

      // Perform local analysis (unless explicitly skipped)
      const localAnalysis = options.skipLocalAnalysis
        ? {
            suspicious_headers: false,
            missing_sec_ch_ua: false,
            datacenter_ip: false,
            local_score: 0,
            needs_verification: true,
            flags: ['local_analysis_skipped'],
          }
        : analyzeRequest(metadata);

      if (this.config.debug) {
        console.log('[WebDecoy] Local analysis result:', localAnalysis);
      }

      // Build detection request
      const detectionRequest: SDKDetectionRequest = {
        request_metadata: metadata,
        local_analysis: localAnalysis,
      };

      // Send to server if verification is needed or TLS fingerprinting is enabled
      const shouldCallServer =
        localAnalysis.needs_verification ||
        (this.config.enableTLSFingerprinting && metadata.tls_info);

      if (!shouldCallServer && localAnalysis.local_score < 50) {
        // Low risk, allow without server verification
        return {
          allowed: true,
          detection: {
            decision: 'allow',
            confidence: 100 - localAnalysis.local_score,
            threat_level: 'MINIMAL',
            bot_detected: false,
            detection_id: 'local_' + Date.now(),
            rule_enforced: false,
          },
          ruleResult: ruleResult ?? undefined,
        };
      }

      // Call the detection API
      const detection = await this.client.detect(detectionRequest);

      // Determine if request should be allowed
      const threshold = options.threshold ?? this.config.threatScoreThreshold;
      const allowed = detection.decision === 'allow' || detection.confidence < threshold;

      if (this.config.debug) {
        console.log('[WebDecoy] Server detection result:', {
          decision: detection.decision,
          confidence: detection.confidence,
          allowed,
        });
      }

      return {
        allowed,
        detection,
        ruleResult: ruleResult ?? undefined,
      };
    } catch (error) {
      // Log error if debug is enabled
      if (this.config.debug) {
        console.error('[WebDecoy] Protection error:', error);
      }

      // Return error result
      return {
        allowed: true, // Fail open to avoid blocking legitimate users
        detection: {
          decision: 'allow',
          confidence: 0,
          threat_level: 'MINIMAL',
          bot_detected: false,
          detection_id: 'error_' + Date.now(),
          rule_enforced: false,
        },
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Validate the API key configuration
   * Useful for testing integration during setup
   */
  async validateConfig(): Promise<{ valid: boolean; error?: string }> {
    if (!this.client) {
      return { valid: false, error: 'No API key configured' };
    }
    try {
      const isValid = await this.client.validateAPIKey();
      return { valid: isValid };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Attach a violation reporter for sending violations to the backend.
   * Called internally when apiKey is present and rules are configured.
   */
  setViolationReporter(reporter: { report(violations: ViolationEvent[]): void; flush(): Promise<void>; destroy(): Promise<void> }): void {
    this.violationReporter = reporter;
  }

  /**
   * Get the API client (for use by violation reporter, enrichment, etc.)
   */
  getClient(): WebDecoyClient | null {
    return this.client;
  }

  /**
   * Get the current configuration
   */
  getConfig(): Readonly<typeof this.config> {
    return { ...this.config };
  }

  /**
   * Clean up resources (timers, flush pending violations)
   */
  async destroy(): Promise<void> {
    this.ruleEngine?.destroy();
    if (this.violationReporter) {
      await this.violationReporter.destroy();
    }
  }
}
