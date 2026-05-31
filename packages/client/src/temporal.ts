/** Temporal signal collector: page-load → interaction → click timing + PoW. */

import { sha256 } from './sha256';

export class TemporalCollector {
  private pageLoadTime: number;
  private firstInteractionTime: number | null = null;
  powResult: Record<string, unknown> | null = null;

  constructor() {
    this.pageLoadTime = performance.now();
  }

  recordFirstInteraction(): void {
    if (!this.firstInteractionTime) {
      this.firstInteractionTime = performance.now();
    }
  }

  /** Legacy single-threaded PoW (prefer PoWManager). */
  async performProofOfWork(difficulty = 4): Promise<Record<string, unknown>> {
    const prefix = `${Date.now()}:${Math.random().toString(36).slice(2)}`;
    const target = '0'.repeat(difficulty);
    const startTime = performance.now();
    let nonce = 0;
    let iterations = 0;

    for (;;) {
      const hash = await sha256(`${prefix}:${nonce}`);
      iterations++;

      if (hash.startsWith(target)) {
        this.powResult = {
          prefix,
          nonce,
          hash,
          iterations,
          duration: performance.now() - startTime,
          difficulty,
        };
        return this.powResult;
      }

      nonce++;
      if (iterations % 1000 === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
  }

  collect(clickTime?: number): Record<string, unknown> {
    const performanceTiming: Record<string, number> = {};
    if (performance.timing) {
      const timing = performance.timing;
      performanceTiming.dnsLookup = timing.domainLookupEnd - timing.domainLookupStart;
      performanceTiming.tcpConnection = timing.connectEnd - timing.connectStart;
      performanceTiming.serverResponse = timing.responseEnd - timing.requestStart;
      performanceTiming.domLoad = timing.domContentLoadedEventEnd - timing.navigationStart;
      performanceTiming.fullLoad = timing.loadEventEnd - timing.navigationStart;
    }

    return {
      pageLoadToFirstInteraction: this.firstInteractionTime
        ? this.firstInteractionTime - this.pageLoadTime
        : null,
      firstInteractionToClick:
        this.firstInteractionTime && clickTime ? clickTime - this.firstInteractionTime : null,
      totalSessionTime: performance.now() - this.pageLoadTime,
      performanceTiming,
      pow: this.powResult,
    };
  }
}
