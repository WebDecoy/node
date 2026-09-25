/**
 * Counts visits AI products send to this application, and reports the totals.
 *
 * Aggregate counts only: an AI platform, a landing path and a number, sent
 * about once a minute. Nothing about a visitor (no IP, user agent, cookie,
 * query string or full referrer) is kept or sent. Only a browser loading a
 * page counts: a GET whose fetch metadata says it is a document navigation.
 * Subresources, API calls and clients that send no fetch metadata are not
 * visits and are never counted.
 */
import type { RequestMetadata } from '../types';
import { classifyReferral } from './llm-referral';

/** Width of the landing path WebDecoy stores. */
const MAX_PATH = 500;

/** Distinct platform and path pairs held before an early send. */
const MAX_ENTRIES = 500;

export interface AIReferralEntry {
  platform: string;
  path: string;
  count: number;
}

export interface AIReferralBatch {
  report_id: string;
  source: 'sdk';
  referrals: AIReferralEntry[];
}

/** What the counter needs from the API client. Resolves true when accepted. */
export interface AIReferralSender {
  sendAIReferrals(batch: AIReferralBatch): Promise<boolean>;
}

export interface AIReferralCounterConfig {
  /** How often to send, in milliseconds (default 60000). */
  flushInterval?: number;
}

const header = (headers: Record<string, string>, name: string): string => {
  const v = headers[name] ?? headers[name.toLowerCase()];
  if (v !== undefined) return v;
  for (const [k, value] of Object.entries(headers)) if (k.toLowerCase() === name) return value;
  return '';
};

export class AIReferralCounter {
  private counts = new Map<string, AIReferralEntry>();
  /** A batch that failed to send, retried under the same id so it counts once. */
  private pending: AIReferralBatch | null = null;
  private flushing = false;
  private timer: ReturnType<typeof setInterval>;

  constructor(
    private readonly sender: AIReferralSender,
    config: AIReferralCounterConfig = {}
  ) {
    this.timer = setInterval(() => void this.flush(), config.flushInterval ?? 60_000);
    this.timer.unref?.();
  }

  /** Count the request if it is a page visit an AI product sent. Never throws. */
  observe(metadata: RequestMetadata): void {
    try {
      if ((metadata.method ?? '').toUpperCase() !== 'GET') return;
      const headers = metadata.headers ?? {};
      if (header(headers, 'sec-fetch-mode') !== 'navigate') return;
      const dest = header(headers, 'sec-fetch-dest');
      if (dest && dest !== 'document') return;
      const path = (metadata.path || '/').split('?')[0] || '/';
      const query = metadata.query ? `?${metadata.query}` : '';
      const platform = classifyReferral(header(headers, 'referer'), `https://site.invalid${path}${query}`);
      if (!platform) return;
      const landing = path.length > MAX_PATH ? path.slice(0, MAX_PATH) : path;
      const key = `${platform}\n${landing}`;
      const entry = this.counts.get(key);
      if (entry) {
        entry.count++;
      } else {
        this.counts.set(key, { platform, path: landing, count: 1 });
        if (this.counts.size >= MAX_ENTRIES) void this.flush();
      }
    } catch {
      // Counting must never affect the request.
    }
  }

  /** Send what has been counted. Never rejects. */
  async flush(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;
    try {
      if (!this.pending && this.counts.size > 0) {
        this.pending = { report_id: crypto.randomUUID(), source: 'sdk', referrals: [...this.counts.values()] };
        this.counts = new Map();
      }
      if (this.pending && (await this.sender.sendAIReferrals(this.pending))) {
        this.pending = null;
      }
    } catch {
      // Kept in `pending` and retried under the same id at the next flush.
    } finally {
      this.flushing = false;
    }
  }

  /** Stop the timer and send what is left. */
  async destroy(): Promise<void> {
    clearInterval(this.timer);
    await this.flush();
  }
}
