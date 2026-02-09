/**
 * Violation Reporter
 * Buffers violation events and flushes them to the backend in batches
 */

import type { WebDecoyClient } from './client';
import type { ViolationEvent } from './rules/types';

export interface ViolationReporterConfig {
  /** Flush interval in milliseconds (default: 5000) */
  flushInterval?: number;
  /** Max buffer size before auto-flush (default: 50) */
  maxBufferSize?: number;
  /** Enable debug logging */
  debug?: boolean;
}

export class ViolationReporter {
  private client: WebDecoyClient;
  private buffer: ViolationEvent[] = [];
  private flushTimer: ReturnType<typeof setInterval>;
  private maxBufferSize: number;
  private debug: boolean;
  private flushing = false;

  constructor(client: WebDecoyClient, config: ViolationReporterConfig = {}) {
    this.client = client;
    this.maxBufferSize = config.maxBufferSize ?? 50;
    this.debug = config.debug ?? false;

    const flushInterval = config.flushInterval ?? 5000;
    this.flushTimer = setInterval(() => this.flush(), flushInterval);
    if (this.flushTimer.unref) {
      this.flushTimer.unref();
    }
  }

  /**
   * Add violations to the buffer. Auto-flushes when buffer reaches maxBufferSize.
   */
  report(violations: ViolationEvent[]): void {
    this.buffer.push(...violations);

    if (this.buffer.length >= this.maxBufferSize) {
      // Fire-and-forget flush
      this.flush().catch(() => {});
    }
  }

  /**
   * Flush buffered violations to the backend
   */
  async flush(): Promise<void> {
    if (this.flushing || this.buffer.length === 0) return;
    this.flushing = true;

    // Drain the buffer
    const events = this.buffer.splice(0, this.buffer.length);

    try {
      // Split into batches of 100 (API limit)
      for (let i = 0; i < events.length; i += 100) {
        const batch = events.slice(i, i + 100);
        await this.client.sendViolations(batch);

        if (this.debug) {
          console.log(`[WebDecoy] Flushed ${batch.length} violation events`);
        }
      }
    } catch (error) {
      if (this.debug) {
        console.error('[WebDecoy] Failed to flush violations:', error);
      }
      // Violations are dropped on failure — no retry, no user impact
    } finally {
      this.flushing = false;
    }
  }

  /**
   * Flush remaining events and stop the timer
   */
  async destroy(): Promise<void> {
    clearInterval(this.flushTimer);
    await this.flush();
  }
}
