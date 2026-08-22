/**
 * What the SDK concluded about one request, and why.
 *
 * WHY THIS MODULE EXISTS
 *
 * `protect()` used to return `{ allowed, detection }` and the adapters typed the
 * value they handed to `onBlocked` as `any`. A developer integrating us had to
 * destructure a blob and string-match to find out which rule fired, and there
 * was nowhere to put three things the SDK already knew:
 *
 * - **Which rules ran.** The engine collapsed to a single deciding rule plus a
 *   violations array, so a filter rule that never ran for want of enrichment was
 *   indistinguishable from one that ran and passed.
 * - **"Challenge this one."** The captcha in `@webdecoy/client` had no verdict
 *   that could route to it, so it was reachable only by wiring it up by hand.
 * - **A stable id.** `'rule_' + Date.now()` is not unique under concurrency and
 *   correlates with nothing in the dashboard.
 *
 * `allowed` still means exactly what it meant before, including failing open on
 * ERROR, so existing middleware keeps working unchanged.
 */

import type { SDKDetectionResponse } from './types';
import type { RuleEngineResult } from './rules/types';
import type { AgentVerdict } from './agent/types';
import type { EdgeVerdict } from './edge';
import { randomHex } from './webcrypto';

/**
 * The outcome of a decision.
 *
 * `ERROR` is not a synonym for `DENY`. It means the SDK could not reach a
 * verdict — the detection call failed, the request was malformed — and the
 * request is allowed through, because a security control that takes the site
 * down when it has a bad day is worse than the traffic it was filtering.
 */
export type Conclusion = 'ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR';

/**
 * Whether a rule actually contributed to the decision.
 *
 * - `RUN` — evaluated, and its conclusion counts.
 * - `DRY_RUN` — evaluated, and its conclusion is recorded but not enforced.
 * - `NOT_RUN` — could not evaluate, because a signal it needs was absent. A
 *   filter rule with no IP enrichment, a Web Bot Auth rule on a request with no
 *   host. This is the state that used to be invisible: such a rule reported
 *   ALLOW, which reads as "checked and fine" rather than "never checked".
 * - `CACHED` — not evaluated; a prior decision for this key was reused.
 */
export type RuleState = 'RUN' | 'DRY_RUN' | 'NOT_RUN' | 'CACHED';

/** One rule's contribution to a decision. */
export interface RuleOutcome {
  /** The rule's name, e.g. `tripwire` or `rate-limit:100/60s`. */
  rule: string;
  state: RuleState;
  conclusion: Conclusion;
  /** The raw rule action, for rules that distinguish throttling from denial. */
  action?: 'ALLOW' | 'DENY' | 'THROTTLE';
  reason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * The result of `protect()`.
 *
 * Kept as an interface separate from the class so that the shape is what
 * consumers depend on. The class exists to carry the narrowing helpers.
 */
export interface ProtectResult {
  /** Unique id for this decision. Correlates with the dashboard. */
  readonly id: string;

  readonly conclusion: Conclusion;

  /**
   * Whether to serve the request.
   *
   * True for `ALLOW` and for `ERROR` (fail open); false for `DENY` and
   * `CHALLENGE`. Unchanged from before the typed decision existed.
   */
  readonly allowed: boolean;

  /** Every rule that was configured, and what it concluded. */
  readonly results: readonly RuleOutcome[];

  /** The deciding reason, when there is one. */
  readonly reason?: string;

  /** Detection response from the service, or the locally-synthesised one. */
  readonly detection: SDKDetectionResponse;

  /** Error message when `conclusion` is `ERROR`. */
  readonly error?: string;

  /** The rule engine's raw result, for callers that were already using it. */
  readonly ruleResult?: RuleEngineResult;

  /**
   * Web Bot Auth verdict, present when a `webBotAuth()` rule triggered local
   * agent verification. Lets middleware treat a `verified` agent specially
   * without re-verifying.
   */
  readonly agent?: AgentVerdict;

  /**
   * What the edge validator said about this request, parsed from
   * `x-wd-clearance` and `x-wd-class`.
   *
   * Always present. Check `edge.present` before branching: false means the edge
   * did not front this request, which is no information rather than a clean
   * bill of health.
   */
  readonly edge?: EdgeVerdict;

  /** The characteristic key this decision was made for. */
  readonly key?: string;

  /** How long this decision may be reused, in milliseconds. 0 means never. */
  readonly ttl: number;

  isAllowed(): boolean;
  isDenied(): boolean;
  isChallenged(): boolean;
  isErrored(): boolean;

  /** Whether a named rule denied the request. */
  deniedBy(rule: string): boolean;
}

export interface DecisionInit {
  conclusion: Conclusion;
  detection: SDKDetectionResponse;
  results?: RuleOutcome[];
  reason?: string;
  error?: string;
  ruleResult?: RuleEngineResult;
  agent?: AgentVerdict;
  edge?: EdgeVerdict;
  key?: string;
  ttl?: number;
  id?: string;
}

/**
 * A decision id.
 *
 * Random rather than sequential: ids leave the process (they go on the
 * detection row and into customers' logs), and a counter would leak request
 * volume to anyone who saw two of them.
 */
export function newDecisionId(): string {
  return `dec_${randomHex(12)}`;
}

export class Decision implements ProtectResult {
  readonly id: string;
  readonly conclusion: Conclusion;
  readonly results: readonly RuleOutcome[];
  readonly reason?: string;
  readonly detection: SDKDetectionResponse;
  readonly error?: string;
  readonly ruleResult?: RuleEngineResult;
  readonly agent?: AgentVerdict;
  readonly edge?: EdgeVerdict;
  readonly key?: string;
  readonly ttl: number;

  constructor(init: DecisionInit) {
    this.id = init.id ?? newDecisionId();
    this.conclusion = init.conclusion;
    this.results = Object.freeze([...(init.results ?? [])]);
    this.reason = init.reason;
    this.detection = init.detection;
    this.error = init.error;
    this.ruleResult = init.ruleResult;
    this.agent = init.agent;
    this.edge = init.edge;
    this.key = init.key;
    this.ttl = init.ttl ?? 0;
  }

  get allowed(): boolean {
    return this.conclusion === 'ALLOW' || this.conclusion === 'ERROR';
  }

  isAllowed(): boolean {
    return this.conclusion === 'ALLOW';
  }

  isDenied(): boolean {
    return this.conclusion === 'DENY';
  }

  isChallenged(): boolean {
    return this.conclusion === 'CHALLENGE';
  }

  isErrored(): boolean {
    return this.conclusion === 'ERROR';
  }

  deniedBy(rule: string): boolean {
    return this.results.some(
      (r) => r.rule === rule && r.state === 'RUN' && r.conclusion === 'DENY',
    );
  }

  /** A copy of this decision with the edge verdict attached. */
  withEdge(edge: EdgeVerdict | undefined): Decision {
    return new Decision({ ...this.init(), edge });
  }

  /** A copy marked as served from cache, with every rule re-stated as CACHED. */
  asCached(): Decision {
    return new Decision({
      ...this.init(),
      results: this.results.map((r) => ({ ...r, state: 'CACHED' as const })),
    });
  }

  private init(): DecisionInit {
    return {
      id: this.id,
      conclusion: this.conclusion,
      results: [...this.results],
      reason: this.reason,
      detection: this.detection,
      error: this.error,
      ruleResult: this.ruleResult,
      agent: this.agent,
      edge: this.edge,
      key: this.key,
      ttl: this.ttl,
    };
  }
}
