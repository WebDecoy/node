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
import { resolveLogger } from './logger';
import type { Logger } from './logger';
import { Decision, newDecisionId } from './decision';
import type { Conclusion } from './decision';
import { deriveKey, DEFAULT_CHARACTERISTICS } from './characteristics';
import { DecisionCache } from './decision-cache';
import { classifyUserAgent } from './bots';
import { isTestTriggerUserAgent } from './test-trigger';
import type { Rule, RuleContext, RuleEngineResult, ViolationEvent } from './rules/types';
import {
  WebDecoyConfig,
  RequestMetadata,
  ProtectOptions,
  SDKDetectionRequest,
  SDKDetectionResponse,
} from './types';

export class WebDecoy {
  private client: WebDecoyClient | null;
  private config: Omit<
    Required<WebDecoyConfig>,
    'apiKey' | 'rules' | 'webBotAuth' | 'characteristics' | 'decisionCache' | 'logger'
  > & {
    apiKey?: string;
  };
  private ruleEngine: RuleEngine | null;
  private violationReporter: { report(violations: ViolationEvent[]): void; flush(): Promise<void>; destroy(): Promise<void> } | null = null;
  private ipEnrichmentClient: IPEnrichmentClient | null = null;
  private _hasFilterRules = false;
  private _hasAgentRules = false;
  private _preparingRules: Rule[] = [];
  private agentVerifier: AgentVerifier | null = null;
  private readonly webBotAuthOptions?: WebDecoyConfig['webBotAuth'];
  private readonly characteristics: readonly import('./characteristics').Characteristic[];
  /** Where diagnostics go. Never console directly — see logger.ts. */
  readonly log: Logger;
  private readonly decisionCache: DecisionCache | null;

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

    this.log = resolveLogger(config.logger, this.config.debug);

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
      this.log.info('Running in local-only mode (no API key). Rules will still evaluate.');
    }

    this.webBotAuthOptions = config.webBotAuth;
    this.characteristics = config.characteristics ?? DEFAULT_CHARACTERISTICS;
    this.decisionCache =
      config.decisionCache === false ? null : new DecisionCache(config.decisionCache ?? {});

    // Rules. When none are configured, tripwires are switched on rather than
    // leaving the SDK with nothing to detect.
    //
    // WHY: server-side detection has almost no signal available to it. The
    // unified score weights honeypot hits at 38% and attack signatures at 24%,
    // but user-agent at 1% and headers at 1% — deliberately, because both are
    // trivially spoofed. A middleware with no rules can only contribute those
    // last two, so it scores ~0 no matter what it sees — while the same client
    // walking into a tripwire scores an order of magnitude higher.
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
      // A rule with a networked store consumes it before evaluation, so the
      // synchronous evaluate() can stay synchronous.
      this._preparingRules = rules.filter((r) => typeof r.prepare === 'function');
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

    this.log.debug('Initialized', {
      apiUrl: this.config.apiUrl,
      enableTLSFingerprinting: this.config.enableTLSFingerprinting,
      threatScoreThreshold: this.config.threatScoreThreshold,
      hasApiKey,
      rulesCount: rules.length,
    });
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

  /**
   * Register a rule after construction.
   *
   * For signals whose definition is not available synchronously — the site
   * honeytoken's path is derived by async HMAC, so the adapter arms it once the
   * derivation settles. Creates the engine if there was none, so an SDK built
   * with `rules: []` can still gain one.
   */
  addRule(rule: import('./rules/types').Rule): void {
    if (!this.ruleEngine) {
      this.ruleEngine = new RuleEngine([rule]);
    } else {
      this.ruleEngine.add(rule);
    }
    if (rule.name.startsWith('filter:')) this._hasFilterRules = true;
    if (rule.name === 'web-bot-auth') this._hasAgentRules = true;
    if (typeof rule.prepare === 'function') this._preparingRules.push(rule);
  }

  /** Build the base (synchronous) rule context from request metadata. */
  private buildContext(metadata: RequestMetadata): RuleContext {
    const context: RuleContext = {
      ip: metadata.ip,
      path: metadata.path,
      method: metadata.method,
      userAgent: metadata.user_agent,
      headers: metadata.headers,
      query: metadata.query,
      body: metadata.body,
      timestamp: metadata.timestamp || Date.now(),
      // Parsed synchronously and unconditionally: it is two header reads,
      // it needs no network, and a rule that has to check whether the edge
      // verdict was populated is a rule people will get wrong.
      edge: readEdgeVerdict(metadata.headers),
      // Same reasoning as `edge`, and the same cost profile: a memoised
      // substring scan over a static table, no network, no async. Populating it
      // unconditionally means a rule never has to ask whether classification
      // ran.
      bot: classifyUserAgent(metadata.user_agent),
    };
    // Derived after the rest of the context exists, because a custom
    // characteristic is handed the context and may read any of it.
    context.key = deriveKey(context, this.characteristics);
    return context;
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

    // Let rules resolve their own networked signals. Run together rather than
    // in sequence: two rate limits against the same store are two round trips
    // whether or not we wait for the first, and the request is waiting on both.
    if (this._preparingRules.length > 0) {
      await Promise.all(this._preparingRules.map((rule) => rule.prepare!(context)));
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
   * @returns The decision — `conclusion`, every rule's outcome, and the
   *   narrowing helpers. Satisfies `ProtectResult`.
   */
  async protect(
    metadata: RequestMetadata,
    options: ProtectOptions = {}
  ): Promise<Decision> {
    // The edge verdict is attached here rather than at each return inside
    // decide(), which has six of them including two fail-open paths. It is
    // information ABOUT the request, not a product of the decision, so it must be
    // present on every outcome — and a per-return copy is a line someone would
    // eventually forget on the branch that mattered.
    const edge = readEdgeVerdict(metadata.headers);
    return (await this.decide(metadata, options)).withEdge(edge);
  }

  private async decide(
    metadata: RequestMetadata,
    options: ProtectOptions = {}
  ): Promise<Decision> {
    // Declared out here so the catch below can stamp the same id and key onto
    // an ERROR decision. An error is still a decision about a caller.
    const id = newDecisionId();
    let key = metadata.ip || 'unknown';

    try {
      // Validate required fields
      if (!metadata.ip) {
        throw new Error('IP address is required in request metadata');
      }

      // Ensure timestamp is set
      if (!metadata.timestamp) {
        metadata.timestamp = Date.now();
      }

      // The reserved test trigger: `curl -A "WebDecoy-Test/1.0"` from the
      // quickstart. Handled BEFORE rules and before any local-analysis
      // threshold: the documented one-liner must always produce a detection,
      // and it must never fire the customer's rules — ingest marks the row
      // is_test and keeps it out of stats, billing, and enforcement.
      if (isTestTriggerUserAgent(metadata.user_agent)) {
        return this.reportTestTrigger(metadata, id);
      }

      // One context for the whole decision. Async only when a rule needs a
      // pre-fetched signal — IP enrichment (filter rules) or Web Bot Auth
      // verification (webBotAuth rules).
      const needsAsync =
        this._hasFilterRules || this._hasAgentRules || this._preparingRules.length > 0;
      const context = needsAsync
        ? await this.buildAsyncContext(metadata)
        : this.buildContext(metadata);
      key = context.key ?? key;
      const agentVerdict: AgentVerdict | undefined = context.agent;
      const ruleResult: RuleEngineResult | null = this.ruleEngine
        ? this.runRules(context)
        : null;

      // Rules denied or throttled: decided locally, no API call. Not cached —
      // a rate limiter has to see every request to advance its window, and a
      // cached tripwire hit would stop the violation being reported.
      if (ruleResult && ruleResult.action !== 'ALLOW') {
        const throttled = ruleResult.action === 'THROTTLE';
        return new Decision({
          conclusion: 'DENY',
          reason: ruleResult.reason,
          detection: {
            decision: 'block',
            confidence: 100,
            threat_level: throttled ? 'MEDIUM' : 'HIGH',
            bot_detected: false,
            detection_id: id,
            rule_enforced: true,
          },
          id,
          results: ruleResult.results,
          ruleResult,
          agent: agentVerdict,
          key,
        });
      }

      // No API client — local rules are all there is, and they allowed.
      if (!this.client) {
        return new Decision({
          conclusion: 'ALLOW',
          detection: {
            decision: 'allow',
            confidence: 0,
            threat_level: 'MINIMAL',
            bot_detected: false,
            detection_id: id,
            rule_enforced: false,
          },
          id,
          results: ruleResult?.results ?? [],
          ruleResult: ruleResult ?? undefined,
          agent: agentVerdict,
          key,
        });
      }

      // A decision we already paid a round trip for. Checked here rather than
      // at the top of the method so the rules still run: the limiter has to see
      // every request, and a tripwire hit still has to be reported.
      const cached = this.decisionCache?.get(key);
      if (cached) return cached.asCached();

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

      this.log.debug('Local analysis', { ...localAnalysis });

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
        return new Decision({
          conclusion: 'ALLOW',
          detection: {
            decision: 'allow',
            confidence: 100 - localAnalysis.local_score,
            threat_level: 'MINIMAL',
            bot_detected: false,
            detection_id: id,
            rule_enforced: false,
          },
          id,
          results: ruleResult?.results ?? [],
          ruleResult: ruleResult ?? undefined,
          agent: agentVerdict,
          key,
        });
      }

      // Call the detection API
      const detection = await this.client.detect(detectionRequest);

      // Determine if request should be allowed
      const threshold = options.threshold ?? this.config.threatScoreThreshold;
      const allowed = detection.decision === 'allow' || detection.confidence < threshold;

      this.log.debug('Server detection', {
        decision: detection.decision,
        confidence: detection.confidence,
        allowed,
      });

      // A server verdict of "challenge" is the one case that can route to the
      // captcha, and it only counts when the score cleared the threshold —
      // below it, the request is allowed and there is nothing to challenge.
      const conclusion: Conclusion = allowed
        ? 'ALLOW'
        : detection.decision === 'challenge'
          ? 'CHALLENGE'
          : 'DENY';

      const decision = new Decision({
        conclusion,
        reason: allowed ? undefined : `Threat score ${detection.confidence} (threshold ${threshold})`,
        detection,
        id,
        results: ruleResult?.results ?? [],
        ruleResult: ruleResult ?? undefined,
        agent: agentVerdict,
        key,
        ttl: this.decisionCache && !allowed ? this.decisionCache.lifetime : 0,
      });

      // Only the network-derived verdicts are worth remembering; see
      // decision-cache.ts for why ALLOW and rule outcomes are excluded.
      if (this.decisionCache) this.decisionCache.set(key, decision);

      return decision;
    } catch (error) {
      // An error here means no verdict was reached, which the operator wants to
      // know about whether or not they turned debug on.
      this.log.error('Protection error', {
        error: error instanceof Error ? error.message : String(error),
      });

      // Fail open: a security control that takes the site down when it has a
      // bad day is worse than the traffic it was filtering. ERROR is a distinct
      // conclusion so a caller can tell "allowed" from "never decided".
      return new Decision({
        conclusion: 'ERROR',
        detection: {
          decision: 'allow',
          confidence: 0,
          threat_level: 'MINIMAL',
          bot_detected: false,
          detection_id: id,
          rule_enforced: false,
        },
        id,
        key,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Report a test-trigger request and return a blocking verdict.
   *
   * The verdict is `allowed: false` so an enforce-mode adapter answers the
   * curl with a 403 — a visibly different response that tells the developer
   * their middleware acted, Arcjet-quickstart style. (The default monitor
   * mode still serves the request; the dashboard row is the real receipt.)
   *
   * Without an API key nothing can reach the dashboard, so the verdict says
   * so via `error` instead of pretending the test ran.
   */
  private async reportTestTrigger(metadata: RequestMetadata, id: string): Promise<Decision> {
    const blocked: SDKDetectionResponse = {
      decision: 'block',
      confidence: 100,
      threat_level: 'HIGH',
      bot_detected: true,
      bot_type: 'test_trigger',
      detection_id: id,
      rule_enforced: false,
    };

    if (!this.client) {
      return new Decision({
        id,
        conclusion: 'DENY',
        reason: 'Reserved test trigger',
        detection: blocked,
        error:
          'Test trigger recognized, but no apiKey is configured — nothing was reported to the dashboard.',
      });
    }

    try {
      const detection = await this.client.detect({
        request_metadata: metadata,
        local_analysis: {
          suspicious_headers: false,
          missing_sec_ch_ua: false,
          datacenter_ip: false,
          local_score: 100,
          needs_verification: true,
          flags: ['test_trigger'],
        },
      });
      return new Decision({
        id,
        conclusion: 'DENY',
        reason: 'Reserved test trigger',
        detection,
      });
    } catch (error) {
      // Still block — the developer asked for a visible reaction — but say
      // why the dashboard may show nothing.
      return new Decision({
        id,
        conclusion: 'DENY',
        reason: 'Reserved test trigger',
        detection: blocked,
        error: error instanceof Error ? error.message : 'Failed to report test detection',
      });
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
