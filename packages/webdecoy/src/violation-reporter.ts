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

/**
 * Most events held while WebDecoy is unavailable. The oldest are dropped past
 * this, so an outage can never grow the process's memory without bound.
 */
export const MAX_BUFFERED_VIOLATIONS = 1_000;

/** Delivery counters for this SDK instance. */
export interface ViolationDeliveryStats {
  /** Events in batches acknowledged by ingest. */
  acknowledgedEvents: number;
  /** HTTP or transport failures for attempted batches. */
  failedBatches: number;
  /** Events discarded after failure, overflow, or shutdown. */
  droppedEvents: number;
  /** Events waiting for an attempt. */
  bufferedEvents: number;
}

export class ViolationReporter {
  private client: WebDecoyClient;
  private buffer: ViolationEvent[] = [];
  private flushTimer: ReturnType<typeof setInterval>;
  private maxBufferSize: number;
  private debug: boolean;
  private flushPromise: Promise<void> | undefined;
  private queuedFlush: Promise<void> | undefined;
  private acknowledgedEvents = 0;
  private failedBatches = 0;
  private droppedEvents = 0;

  constructor(client: WebDecoyClient, config: ViolationReporterConfig = {}) {
    this.client = client;
    this.maxBufferSize = config.maxBufferSize ?? 50;
    this.debug = config.debug ?? false;

    const flushInterval = config.flushInterval ?? 5000;
    // flush() catches everything internally and never rejects, so `void` is the
    // whole handling. Said out loud because a timer whose callback rejects
    // keeps firing and every tick adds another unhandled rejection.
    this.flushTimer = setInterval(() => void this.flush(), flushInterval);
    if (this.flushTimer.unref) {
      this.flushTimer.unref();
    }
  }

  /**
   * Add violations to the buffer. Auto-flushes when buffer reaches maxBufferSize.
   */
  report(violations: ViolationEvent[]): void {
    this.buffer.push(...violations);
    if (this.buffer.length > MAX_BUFFERED_VIOLATIONS) {
      const overflow = this.buffer.length - MAX_BUFFERED_VIOLATIONS;
      this.buffer.splice(0, overflow);
      this.droppedEvents += overflow;
    }

    if (this.buffer.length >= this.maxBufferSize) {
      // Fire-and-forget flush
      this.flush().catch(() => {});
    }
  }

  /** Flush the buffer, coalescing requests that arrive during an active send. */
  flush(): Promise<void> {
    if (this.queuedFlush) return this.queuedFlush;
    if (this.flushPromise) {
      if (this.buffer.length === 0 || !this.client.isAvailable()) return this.flushPromise;
      this.queuedFlush = this.flushPromise.then(() => {
        this.queuedFlush = undefined;
        return this.flush();
      });
      return this.queuedFlush;
    }
    if (this.buffer.length === 0 || !this.client.isAvailable()) return Promise.resolve();

    const size = this.buffer.length;
    this.flushPromise = Promise.resolve()
      .then(() => this.flushBatches(size))
      .finally(() => { this.flushPromise = undefined; });
    return this.flushPromise;
  }

  private async flushBatches(remaining: number): Promise<void> {
    // Keep unattempted events buffered when an HTTP or transport failure pauses
    // the client. Each request respects the ingest limit of 100 events.
    while (remaining > 0 && this.buffer.length > 0 && this.client.isAvailable()) {
      const batch = this.buffer.splice(0, Math.min(100, remaining));
      remaining -= batch.length;
      if (await this.client.sendViolationBatch(batch)) {
        this.acknowledgedEvents += batch.length;
        if (this.debug) {
          console.log(`[WebDecoy] Flushed ${batch.length} violation events`);
        }
      } else {
        // A failed response can follow a successful server write. Replaying
        // an attempted batch would duplicate violations and tripwire effects.
        this.failedBatches++;
        this.droppedEvents += batch.length;
      }
    }
  }

  getDeliveryStats(): ViolationDeliveryStats {
    return {
      acknowledgedEvents: this.acknowledgedEvents,
      failedBatches: this.failedBatches,
      droppedEvents: this.droppedEvents,
      bufferedEvents: this.buffer.length,
    };
  }

  /** Stop the timer and give remaining events one final flush. */
  async destroy(): Promise<void> {
    clearInterval(this.flushTimer);
    if (this.flushPromise) await this.flushPromise;
    await this.flush();
    this.droppedEvents += this.buffer.length;
    this.buffer.length = 0;
  }
}
