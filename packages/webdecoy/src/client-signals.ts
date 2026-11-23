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
  /** Identifier used by the store. */
  sessionId: string;
  /** Scope of a receipt issued by the embedded score endpoint. */
  receipt?: { host: string; siteKey: string; expiresAt: number };
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

/** Session references supplied by an existing application integration. */
export const CLIENT_SESSION_COOKIE = 'wd_cs';
export const CLIENT_SESSION_HEADER = 'x-wd-session';

export const CLIENT_RECEIPT_COOKIE = '__Host-wd_cs';
export const CLIENT_RECEIPT_PREFIX = 'receipt:';
export const CLIENT_RECEIPT_TTL_MS = 15 * 60_000;

/** Normalize the request authority for receipt scope checks. */
export function getClientSignalHost(headers: Record<string, string>): string | undefined {
  const value = headers.host ?? headers[':authority'];
  if (typeof value !== 'string' || value.length > 255 || !/^[a-z0-9.:[\]-]+$/i.test(value)) {
    return undefined;
  }
  try {
    return new URL('https://' + value).host || undefined;
  } catch {
    return undefined;
  }
}

function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq >= 0 && part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return undefined;
}

/** Read the server receipt or an application-supplied legacy session id. */
export function readClientSession(headers: Record<string, string>): string | undefined {
  const receipt = readCookie(headers.cookie, CLIENT_RECEIPT_COOKIE);
  if (receipt !== undefined) {
    return /^[0-9a-f]{48}$/.test(receipt) ? CLIENT_RECEIPT_PREFIX + receipt : undefined;
  }
  const legacy = readCookie(headers.cookie, CLIENT_SESSION_COOKIE) || headers[CLIENT_SESSION_HEADER];
  return legacy && !legacy.startsWith(CLIENT_RECEIPT_PREFIX) ? legacy : undefined;
}

export interface ClientSignalConfig {
  /** Where verdicts are read from. Must be the store `/score` writes to. */
  store: ClientSignalStore;
  /** Site key expected by this rule when several site keys share a request host. */
  siteKey?: string;
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
  private readonly siteKey?: string;
  private readonly minScore?: number;
  private readonly action: 'DENY' | 'THROTTLE';
  private readonly dryRun: boolean;

  constructor(config: ClientSignalConfig) {
    this.store = config.store;
    this.siteKey = config.siteKey;
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

    const issuedReceipt = sessionId.startsWith(CLIENT_RECEIPT_PREFIX);
    const receipt = verdict?.receipt;
    const usableReceipt = receipt && Date.now() < receipt.expiresAt
      && getClientSignalHost(context.headers) === receipt.host
      && (this.siteKey === undefined || this.siteKey === receipt.siteKey);
    if (!verdict || verdict.sessionId !== sessionId || ((issuedReceipt || this.siteKey !== undefined) && !usableReceipt)) {
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
        ...(issuedReceipt ? {} : { sessionId }),
        dryRun: this.dryRun,
      },
    };
  }
}

/** Act on the browser widget's verdict for this session. See {@link ClientSignalConfig}. */
export function clientSignals(config: ClientSignalConfig): Rule {
  return new ClientSignalRule(config);
}
