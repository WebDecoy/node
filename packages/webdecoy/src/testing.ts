/**
 * Testing utilities, for the application's test suite rather than ours.
 *
 * WHY THIS EXISTS
 *
 * The SDK has hundreds of tests and a customer had none of them. There was no
 * supported way to write "assert this request would be denied" against your own
 * rules, so the first time anyone learned what the middleware does to their
 * traffic was in production — which is also why `mode: 'monitor'` had to become
 * the default.
 *
 * Three things make that test hard to write by hand, and each is solved here:
 *
 * - **Assembling `RequestMetadata`** is seven fields of boilerplate per case.
 * - **Rate-limit tests would have to sleep.** A window is real time, and a test
 *   that waits sixty seconds is a test nobody runs.
 * - **An API key in the environment turns a unit test into a network call**, and
 *   worse, files test traffic as real detections in the customer's dashboard.
 *
 * Import from `@webdecoy/node/testing` so none of it reaches production bundles.
 *
 * @example
 * ```ts
 * import { createTestHarness, get, expectDenied } from '@webdecoy/node/testing';
 *
 * const wd = createTestHarness({ rules: [tripwire()] });
 *
 * expectDenied(await wd.protect(get('/.env')), { rule: 'tripwire' });
 * expectAllowed(await wd.protect(get('/')));
 * ```
 */

import { WebDecoy } from './sdk';
import type { WebDecoyConfig, RequestMetadata } from './types';
import type { ProtectResult, RuleState } from './decision';
import { silentLogger } from './logger';

/** Build request metadata without seven lines of boilerplate. */
export function request(over: Partial<RequestMetadata> = {}): RequestMetadata {
  return {
    method: 'GET',
    path: '/',
    ip: '203.0.113.1',
    user_agent:
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
    headers: {},
    timestamp: Date.now(),
    ...over,
  };
}

/** `GET path`, with an optional query string taken from the path. */
export function get(path: string, over: Partial<RequestMetadata> = {}): RequestMetadata {
  const q = path.indexOf('?');
  return request({
    method: 'GET',
    path: q === -1 ? path : path.slice(0, q),
    query: q === -1 ? undefined : path.slice(q + 1),
    ...over,
  });
}

/** `POST path`, with an optional text body. */
export function post(
  path: string,
  body?: string,
  over: Partial<RequestMetadata> = {},
): RequestMetadata {
  return { ...get(path, over), method: 'POST', body };
}

/** A request that presents itself as a named bot. */
export function botRequest(userAgent: string, over: Partial<RequestMetadata> = {}): RequestMetadata {
  return request({ user_agent: userAgent, ...over });
}

export interface TestHarnessOptions extends WebDecoyConfig {
  /**
   * Allow the harness to reach the network. Off by default.
   *
   * A `WEBDECOY_API_KEY` in the environment would otherwise turn a unit test
   * into a live call — slow, flaky, and it files test traffic as real detections
   * in the customer's dashboard.
   */
  allowNetwork?: boolean;
}

/**
 * An SDK wired for tests: offline, silent, and with its own rule state.
 *
 * Each harness gets fresh in-memory stores, so rate-limit counters do not leak
 * between test cases the way a shared module-level SDK's would.
 */
export function createTestHarness(options: TestHarnessOptions = {}): WebDecoy {
  const { allowNetwork = false, ...config } = options;
  return new WebDecoy({
    ...config,
    apiKey: allowNetwork ? config.apiKey : undefined,
    logger: config.logger ?? silentLogger,
  });
}

function describeDecision(decision: ProtectResult): string {
  const rules = decision.results
    .map((r) => `${r.rule}=${r.conclusion}${r.state === 'RUN' ? '' : `(${r.state})`}`)
    .join(', ');
  return [
    `conclusion=${decision.conclusion}`,
    decision.reason ? `reason="${decision.reason}"` : null,
    rules ? `rules[${rules}]` : 'rules[none]',
  ]
    .filter(Boolean)
    .join(' ');
}

class AssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebDecoyAssertionError';
  }
}

export interface DeniedExpectation {
  /** The rule that must have denied, e.g. `'tripwire'`. */
  rule?: string;
  /** A substring or pattern the reason must match. */
  reason?: string | RegExp;
}

/**
 * Assert the request was denied.
 *
 * The failure message prints every rule and its state, because "expected false
 * to be true" tells you nothing about which of six rules was supposed to fire.
 */
export function expectDenied(decision: ProtectResult, expected: DeniedExpectation = {}): void {
  if (decision.conclusion !== 'DENY') {
    throw new AssertionError(
      `Expected the request to be denied, but ${describeDecision(decision)}`,
    );
  }
  if (expected.rule && !decision.deniedBy(expected.rule)) {
    throw new AssertionError(
      `Expected ${expected.rule} to deny, but ${describeDecision(decision)}`,
    );
  }
  if (expected.reason !== undefined) {
    const reason = decision.reason ?? '';
    const ok =
      typeof expected.reason === 'string'
        ? reason.includes(expected.reason)
        : expected.reason.test(reason);
    if (!ok) {
      throw new AssertionError(
        `Expected the reason to match ${String(expected.reason)}, got "${reason}"`,
      );
    }
  }
}

/** Assert the request was allowed. `ERROR` fails: it means no verdict was reached. */
export function expectAllowed(decision: ProtectResult): void {
  if (decision.conclusion !== 'ALLOW') {
    throw new AssertionError(
      `Expected the request to be allowed, but ${describeDecision(decision)}`,
    );
  }
}

/** Assert a named rule reached a particular state — `DRY_RUN`, `NOT_RUN`, `CACHED`. */
export function expectRuleState(
  decision: ProtectResult,
  rule: string,
  state: RuleState,
): void {
  const outcome = decision.results.find((r) => r.rule === rule);
  if (!outcome) {
    throw new AssertionError(
      `No rule named ${rule} ran. ${describeDecision(decision)}`,
    );
  }
  if (outcome.state !== state) {
    throw new AssertionError(
      `Expected ${rule} to be ${state}, got ${outcome.state}. ${describeDecision(decision)}`,
    );
  }
}

/**
 * Run `count` requests and return their conclusions.
 *
 * For rate-limit tests, which are otherwise a loop everyone writes slightly
 * differently.
 */
export async function protectMany(
  sdk: WebDecoy,
  metadata: RequestMetadata | (() => RequestMetadata),
  count: number,
): Promise<ProtectResult[]> {
  const out: ProtectResult[] = [];
  for (let i = 0; i < count; i++) {
    out.push(await sdk.protect(typeof metadata === 'function' ? metadata() : { ...metadata }));
  }
  return out;
}
