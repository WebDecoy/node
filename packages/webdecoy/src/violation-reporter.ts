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
  private deliveryTimer: ReturnType<typeof setTimeout> | undefined;
  private flushInterval: number;
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
    this.flushInterval = flushInterval;
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
    // A per-event id lets ingest store each event once, however many times
    // the batch carrying it arrives.
    for (const violation of violations) {
      this.buffer.push(violation.eventId ? violation : { ...violation, eventId: crypto.randomUUID() });
    }
    if (this.buffer.length > MAX_BUFFERED_VIOLATIONS) {
      const overflow = this.buffer.length - MAX_BUFFERED_VIOLATIONS;
      this.buffer.splice(0, overflow);
      this.droppedEvents += overflow;
    }

    if (this.buffer.length >= this.maxBufferSize) {
      // Fire-and-forget flush
      this.flush().catch(() => {});
    } else {
      this.scheduleDelivery();
    }
  }

  /**
   * Give buffered events one delivery attempt before the process can exit.
   *
   * The interval above is unref'd so an idle reporter never holds a process
   * open. On its own that meant a server shut down gracefully (Express after
   * server.close(), Fastify after close(), Hono on Node) exited with its last
   * events unsent and uncounted. This one-shot timer is left ref'd, so a
   * natural exit waits at most one flush interval plus the request timeout.
   * It is not re-armed while the client is paused, so an outage cannot keep
   * the process alive.
   */
  private cancelDelivery(): void {
    clearTimeout(this.deliveryTimer);
    this.deliveryTimer = undefined;
  }

  private scheduleDelivery(): void {
    if (this.deliveryTimer) return;
    this.deliveryTimer = setTimeout(() => {
      this.deliveryTimer = undefined;
      void this.flush();
    }, this.flushInterval);
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
      .finally(() => {
        this.flushPromise = undefined;
        // Nothing left to deliver: stop holding the process open.
        if (this.buffer.length === 0) this.cancelDelivery();
      });
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
    this.cancelDelivery();
    if (this.flushPromise) await this.flushPromise;
    await this.flush();
    this.droppedEvents += this.buffer.length;
    this.buffer.length = 0;
  }
}
