/**
 * What the browser told us, made available to the request that follows.
 *
 * WHY THIS EXISTS
 *
 * `@webdecoy/client` collects behavioural, environmental and form signals and
 * can run proof-of-work; `DetectionEngine` scores them; `/score` already
 * accepted a submission and returned a verdict. The parts were all there and
 * they were not connected: the verdict went back to the browser, and the next
 * request to the origin knew nothing about it. Joining the two was left as an
 * exercise for the developer, so in practice nobody did.
 *
 * That matters because this is the SDK's answer to the one thing a tripwire
 * cannot catch — a real browser, driven by Playwright, that follows no hidden
 * links and requests no honeypot paths. It has a genuine fingerprint and it
 * still cannot fake human interaction. Competitors launched exactly this shape
 * as a headline feature; we have had the parts for longer and no way to use
 * them.
 *
 * WHAT IT IS NOT
 *
 * A client signal is a claim by code running on the client, so it is evidence
 * about a cooperative browser and nothing else. No JavaScript means no signals,
 * which is why {@link ClientSignalRule} treats "absent" as `NOT_RUN` rather than
 * as suspicion: a curl request and a search crawler both send nothing, and
 * scoring silence would deny the crawlers we most need to keep.
 *
 * This augments the keyless deterministic rules. It does not replace them.
 */

import type { Rule, RuleContext, RuleResult } from './rules/types';
import type { Recommendation } from './detection';

/** The engine's verdict on one browser session. */
export interface ClientVerdict {
  /** Session id supplied by the browser widget. */
  sessionId: string;
  /** 0–1, higher is more bot-like. */
  score: number;
  /** What the engine recommends doing about it. */
  recommendation: Recommendation;
  /** When the verdict was recorded, Unix ms. */
  at: number;
}

/**
 * Where verdicts live between the `/score` submission and the requests that
 * follow it.
 *
 * Same sync/async split as the rate-limit store, and for the same reason: an
 * in-memory default must not make every rule evaluation a promise.
 */
export interface ClientSignalStore {
  readonly sync: boolean;
  get(sessionId: string): ClientVerdict | undefined | Promise<ClientVerdict | undefined>;
  set(verdict: ClientVerdict): void | Promise<void>;
}

export interface MemoryClientSignalStoreOptions {
  /** How long a verdict stays usable. @default 900_000 (15 minutes) */
  ttl?: number;
  /** Maximum sessions held. @default 10_000 */
  max?: number;
}

export class MemoryClientSignalStore implements ClientSignalStore {
  readonly sync = true as const;
  private readonly ttl: number;
  private readonly max: number;
  private entries = new Map<string, ClientVerdict>();

  constructor(options: MemoryClientSignalStoreOptions = {}) {
    this.ttl = options.ttl ?? 900_000;
    this.max = options.max ?? 10_000;
  }

  get(sessionId: string): ClientVerdict | undefined {
    const entry = this.entries.get(sessionId);
    if (!entry) return undefined;
    if (Date.now() - entry.at > this.ttl) {
      this.entries.delete(sessionId);
      return undefined;
    }
    return entry;
  }

  set(verdict: ClientVerdict): void {
    this.entries.delete(verdict.sessionId);
    this.entries.set(verdict.sessionId, verdict);
    while (this.entries.size > this.max) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}

/** The cookie the widget sets, and the header it will also accept. */
export const CLIENT_SESSION_COOKIE = 'wd_cs';
export const CLIENT_SESSION_HEADER = 'x-wd-session';

/** Read the browser session id off a request, cookie first then header. */
export function readClientSession(headers: Record<string, string>): string | undefined {
  const cookie = headers['cookie'];
  if (cookie) {
    for (const part of cookie.split(';')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      if (part.slice(0, eq).trim() === CLIENT_SESSION_COOKIE) {
        const value = part.slice(eq + 1).trim();
        if (value) return value;
      }
    }
  }
  const header = headers[CLIENT_SESSION_HEADER];
  return header || undefined;
}

export interface ClientSignalConfig {
  /** Where verdicts are read from. Must be the store `/score` writes to. */
  store: ClientSignalStore;
  /**
   * Deny at or above this score, 0–1. The engine's own `recommendation` is used
   * when this is omitted.
   */
  minScore?: number;
  /** Action on a match. @default 'DENY' */
  action?: 'DENY' | 'THROTTLE';
  /** Log the violation but do not block. */
  dryRun?: boolean;
}

/**
 * Act on what the browser widget reported for this session.
 *
 * A request with no session — no JavaScript, no widget, a crawler, curl — is
 * `NOT_RUN`, never a denial. See the module note.
 */
export class ClientSignalRule implements Rule {
  readonly name = 'client-signals';
  private readonly store: ClientSignalStore;
  private readonly minScore?: number;
  private readonly action: 'DENY' | 'THROTTLE';
  private readonly dryRun: boolean;

  constructor(config: ClientSignalConfig) {
    this.store = config.store;
    this.minScore = config.minScore;
    this.action = config.action ?? 'DENY';
    this.dryRun = config.dryRun ?? false;
  }

  async prepare(context: RuleContext): Promise<void> {
    if (this.store.sync) return;
    const sessionId = readClientSession(context.headers);
    if (!sessionId) return;
    const verdict = await this.store.get(sessionId);
    if (verdict) {
      context.prepared ??= {};
      context.prepared[this.name] = verdict;
    }
  }

  evaluate(context: RuleContext): RuleResult {
    const sessionId = readClientSession(context.headers);
    if (!sessionId) {
      return {
        action: 'ALLOW',
        rule: this.name,
        state: 'NOT_RUN',
        reason: 'No browser session — the client widget did not run for this request',
      };
    }

    const verdict = this.store.sync
      ? (this.store.get(sessionId) as ClientVerdict | undefined)
      : (context.prepared?.[this.name] as ClientVerdict | undefined);

    if (!verdict) {
      return {
        action: 'ALLOW',
        rule: this.name,
        state: 'NOT_RUN',
        reason: 'No signals recorded for this session yet',
      };
    }

    const bad =
      this.minScore !== undefined
        ? verdict.score >= this.minScore
        : verdict.recommendation === 'block';

    if (!bad) {
      return {
        action: 'ALLOW',
        rule: this.name,
        metadata: { score: verdict.score, recommendation: verdict.recommendation },
      };
    }

    return {
      action: this.dryRun ? 'ALLOW' : this.action,
      rule: this.name,
      reason: `Client signals scored ${verdict.score.toFixed(2)} (${verdict.recommendation})`,
      metadata: {
        score: verdict.score,
        recommendation: verdict.recommendation,
        sessionId,
        dryRun: this.dryRun,
      },
    };
  }
}

/** Act on the browser widget's verdict for this session. See {@link ClientSignalConfig}. */
export function clientSignals(config: ClientSignalConfig): Rule {
  return new ClientSignalRule(config);
}
