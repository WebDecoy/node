/**
 * Web Decoy SDK
 * Main SDK class for bot detection and protection
 */

import { WebDecoyClient } from './client';
import { analyzeRequest } from './local-analysis';
import { RuleEngine } from './rules/rule-engine';
import { tripwire } from './rules';
import { ViolationReporter } from './violation-reporter';
import { IPEnrichmentClient } from './ip-enrichment';
import { AgentVerifier } from './agent/verifier';
import type { AgentRequestInput, AgentVerdict } from './agent/types';
import { readEdgeVerdict } from './edge';
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
  private config: Omit<Required<WebDecoyConfig>, 'apiKey' | 'rules' | 'webBotAuth'> & {
    apiKey?: string;
  };
  private ruleEngine: RuleEngine | null;
  private violationReporter: { report(violations: ViolationEvent[]): void; flush(): Promise<void>; destroy(): Promise<void> } | null = null;
  private ipEnrichmentClient: IPEnrichmentClient | null = null;
  private _hasFilterRules = false;
  private _hasAgentRules = false;
  private agentVerifier: AgentVerifier | null = null;
  private readonly webBotAuthOptions?: WebDecoyConfig['webBotAuth'];

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
      apiUrl: config.apiUrl || 'https://ingest.webdecoy.com',
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

    this.webBotAuthOptions = config.webBotAuth;

    // Rules. When none are configured, tripwires are switched on rather than
    // leaving the SDK with nothing to detect.
    //
    // WHY: server-side detection has almost no signal available to it. The
    // unified score weights honeypot hits at 38% and attack signatures at 24%,
    // but user-agent at 1% and headers at 1% — deliberately, because both are
    // trivially spoofed. A middleware with no rules can only contribute those
    // last two, so it scores ~0 no matter what it sees. Measured against
    // production: every `sdk` detection ever recorded scored 0, while
    // `sdk_tripwire` averaged 52.5 and `bot_scanner` 45.7.
    //
    // Inflating the user-agent weight would be the wrong fix and actively
    // backwards: it would score the clients honest enough to say
    // "python-requests" and miss every attacker who simply does not.
    //
    // Tripwires are the signal that works here. The built-in paths are secrets
    // and config files — /.env, /.ssh/id_rsa, /wp-config.php — that no
    // application serves, so a request for one is a scanner enumerating rather
    // than a visitor browsing, and a legitimate visitor cannot trip one by
    // accident. Pass `rules: []` explicitly to opt out.
    const rules = config.rules ?? [tripwire()];
    if (rules.length > 0) {
      this.ruleEngine = new RuleEngine(rules);
      // Check if any filter rules exist (they need async enrichment)
      this._hasFilterRules = rules.some((r) => r.name.startsWith('filter:'));
      // Web Bot Auth rules need the agent verdict precomputed (async) before
      // the synchronous rule can act on it — same pattern as filter rules.
      this._hasAgentRules = rules.some((r) => r.name === 'web-bot-auth');
      if (this._hasAgentRules) {
        // Warm the directory cache so the first protected request verifies warm.
        this.getAgentVerifier().warmup();
      }
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
        rulesCount: rules.length,
      });
    }
  }

  /**
   * Evaluate rules against request metadata (synchronous).
   * Returns null if no rules are configured.
   */
  evaluateRules(metadata: RequestMetadata): RuleEngineResult | null {
    if (!this.ruleEngine) return null;
    return this.runRules(this.buildContext(metadata));
  }

  /**
   * Evaluate rules with async pre-fetch (IP enrichment, Web Bot Auth
   * verification). Use this instead of evaluateRules() when filter rules or
   * webBotAuth() rules are present.
   */
  async evaluateRulesAsync(metadata: RequestMetadata): Promise<RuleEngineResult | null> {
    if (!this.ruleEngine) return null;
    const context = await this.buildAsyncContext(metadata);
    return this.runRules(context);
  }

  /** Build the base (synchronous) rule context from request metadata. */
  private buildContext(metadata: RequestMetadata): RuleContext {
    return {
      ip: metadata.ip,
      path: metadata.path,
      method: metadata.method,
      userAgent: metadata.user_agent,
      headers: metadata.headers,
      timestamp: metadata.timestamp || Date.now(),
      // Parsed synchronously and unconditionally (#481): it is two header reads,
      // it needs no network, and a rule that has to check whether the edge
      // verdict was populated is a rule people will get wrong.
      edge: readEdgeVerdict(metadata.headers),
    };
  }

  /**
   * Build a rule context with async signals resolved: IP enrichment (for
   * filter rules) and the Web Bot Auth verdict (for webBotAuth() rules).
   */
  private async buildAsyncContext(metadata: RequestMetadata): Promise<RuleContext> {
    const context = this.buildContext(metadata);

    // Pre-fetch IP enrichment if we have filter rules and an enrichment client
    if (this._hasFilterRules && this.ipEnrichmentClient) {
      const enrichment = await this.ipEnrichmentClient.enrich(metadata.ip);
      if (enrichment) {
        context.enrichment = enrichment;
      }
    }

    // Verify Web Bot Auth signature locally so the sync rule can act on it.
    if (this._hasAgentRules) {
      context.agent = await this.computeAgentVerdict(metadata);
    }

    return context;
  }

  /** Evaluate rules against a prepared context and report any violations. */
  private runRules(context: RuleContext): RuleEngineResult | null {
    if (!this.ruleEngine) return null;
    const result = this.ruleEngine.evaluate(context);
    if (result.violations.length > 0 && this.violationReporter) {
      this.violationReporter.report(result.violations);
    }
    return result;
  }

  /** Lazily construct the shared Web Bot Auth verifier (one directory cache). */
  private getAgentVerifier(): AgentVerifier {
    if (!this.agentVerifier) {
      this.agentVerifier = new AgentVerifier({
        debug: this.config.debug,
        ...this.webBotAuthOptions,
      });
    }
    return this.agentVerifier;
  }

  /**
   * Verify a request's Web Bot Auth signature locally, deriving the request
   * URL/authority from its metadata. Returns undefined when the request lacks
   * the host information needed to verify (verdict is then simply absent).
   */
  private async computeAgentVerdict(metadata: RequestMetadata): Promise<AgentVerdict | undefined> {
    const input = agentInputFromMetadata(metadata);
    if (!input) return undefined;
    return this.getAgentVerifier().verify(input);
  }

  /**
   * Verify an inbound request's Web Bot Auth signature locally (RFC 9421, tag
   * "web-bot-auth"). Returns whether it is a cryptographically `verified`
   * agent, an `impersonation` of a known one, an unverifiable `claimed`
   * signature, or `none`. No network on the warm path.
   *
   * Accepts a WHATWG `Request` (edge/Next.js) or a `{ method, url, headers }`
   * object (Node).
   *
   * @example
   * ```ts
   * const verdict = await webdecoy.detectBot(request);
   * if (verdict.status === 'impersonation') return new Response('Forbidden', { status: 403 });
   * if (verdict.status === 'verified') console.log('verified agent:', verdict.agentName);
   * ```
   */
  async detectBot(request: AgentRequestInput): Promise<AgentVerdict> {
    return this.getAgentVerifier().verify(request);
  }

  /**
   * Whether this SDK instance has filter rules that need async enrichment
   */
  get hasFilterRules(): boolean {
    return this._hasFilterRules;
  }

  /**
   * Whether this SDK instance has Web Bot Auth rules that need async
   * verification before evaluation.
   */
  get hasAgentRules(): boolean {
    return this._hasAgentRules;
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
    // The edge verdict (#481) is attached here rather than at each return inside
    // decide(), which has seven of them including two fail-open paths. It is
    // information ABOUT the request, not a product of the decision, so it must be
    // present on every outcome — and a per-return copy is a line someone would
    // eventually forget on the branch that mattered.
    const edge = readEdgeVerdict(metadata.headers);
    const result = await this.decide(metadata, options);
    return { ...result, edge };
  }

  private async decide(
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

      // Evaluate rules first (if configured). Use async evaluation when a rule
      // needs a pre-fetched signal — IP enrichment (filter rules) or Web Bot
      // Auth verification (webBotAuth rules). Capture the agent verdict so it
      // can be surfaced on the result for downstream allow decisions.
      let ruleResult: RuleEngineResult | null;
      let agentVerdict: AgentVerdict | undefined;
      if (this.ruleEngine && (this._hasFilterRules || this._hasAgentRules)) {
        const context = await this.buildAsyncContext(metadata);
        agentVerdict = context.agent;
        ruleResult = this.runRules(context);
      } else {
        ruleResult = this.evaluateRules(metadata);
      }

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
          agent: agentVerdict,
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
          agent: agentVerdict,
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
          agent: agentVerdict,
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
          agent: agentVerdict,
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
        agent: agentVerdict,
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

/**
 * Reconstruct a Web Bot Auth verification input from request metadata.
 *
 * Signature verification needs the request's scheme, authority, and path.
 * Metadata carries the path and headers but not a full URL, so the authority
 * comes from the `Host` / `:authority` header and the scheme from
 * `X-Forwarded-Proto` (defaulting to https). Returns null when no host is
 * available — without it `@authority` can't be verified, so we simply skip
 * agent verification rather than guess.
 */
function agentInputFromMetadata(metadata: RequestMetadata): AgentRequestInput | null {
  const headers = metadata.headers || {};
  const host =
    headers['host'] ||
    headers[':authority'] ||
    headers['x-forwarded-host'] ||
    headers['Host'];
  if (!host) return null;

  const proto = headers['x-forwarded-proto'] || headers['X-Forwarded-Proto'];
  const scheme = (proto ? proto.split(',')[0].trim() : 'https') || 'https';

  const rawPath = metadata.path || '/';
  const path = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;

  try {
    return {
      method: metadata.method,
      url: `${scheme}://${host}${path}`,
      headers,
    };
  } catch {
    return null;
  }
}
