/**
 * Web Decoy SDK
 * Main SDK class for bot detection and protection
 */

import { WebDecoyClient } from './client';
import { analyzeRequest } from './local-analysis';
import {
  WebDecoyConfig,
  RequestMetadata,
  ProtectResult,
  ProtectOptions,
  SDKDetectionRequest,
} from './types';

export class WebDecoy {
  private client: WebDecoyClient;
  private config: Required<WebDecoyConfig>;

  constructor(config: WebDecoyConfig) {
    // Validate required config
    if (!config.apiKey) {
      throw new Error('API key is required. Please provide a valid Web Decoy API key.');
    }

    if (!config.apiKey.startsWith('sk_live_') && !config.apiKey.startsWith('sk_test_')) {
      throw new Error(
        'Invalid API key format. API key should start with "sk_live_" or "sk_test_".'
      );
    }

    // Set defaults
    this.config = {
      apiKey: config.apiKey,
      apiUrl: config.apiUrl || 'https://api.webdecoy.com',
      enableTLSFingerprinting: config.enableTLSFingerprinting ?? true,
      threatScoreThreshold: config.threatScoreThreshold ?? 80,
      timeout: config.timeout ?? 5000,
      debug: config.debug ?? false,
    };

    // Initialize API client
    this.client = new WebDecoyClient({
      apiKey: this.config.apiKey,
      apiUrl: this.config.apiUrl,
      timeout: this.config.timeout,
      debug: this.config.debug,
    });

    if (this.config.debug) {
      console.log('[WebDecoy] Initialized with config:', {
        apiUrl: this.config.apiUrl,
        enableTLSFingerprinting: this.config.enableTLSFingerprinting,
        threatScoreThreshold: this.config.threatScoreThreshold,
      });
    }
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
   * Get the current configuration
   */
  getConfig(): Readonly<Required<WebDecoyConfig>> {
    return { ...this.config };
  }
}
