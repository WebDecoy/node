/**
 * Client-side proof-of-work solver.
 *
 * Fetches a challenge from the server, then solves it across multiple inline
 * Web Workers (disjoint nonce slices via striding). Falls back to a local
 * challenge when no server is configured. Ported from FCaptcha client.js.
 */

import { getServerUrl } from './config';
import type { Challenge, PoWSolution } from './types';

export class PoWManager {
  private workers: Worker[] = [];
  challenge: Challenge | null = null;
  solution: PoWSolution | null = null;
  private solving = false;
  private solvePromise: Promise<PoWSolution> | null = null;
  private startTime: number | null = null;

  /**
   * Inline Web Worker for PoW computation. Each worker scans a disjoint nonce
   * slice via `(startNonce + k*stride)`, so N workers explore the space N-way.
   */
  private _createWorker(): Worker {
    const workerCode = `
      async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }

      self.onmessage = async function(e) {
        const { prefix, difficulty, signalsHash, startNonce = 0, stride = 1, batchSize = 10000 } = e.data;
        const target = '0'.repeat(difficulty);
        let nonce = startNonce;
        let iterations = 0;
        const startTime = performance.now();

        const inputPrefix = signalsHash ? prefix + ':' + signalsHash : prefix;

        while (true) {
          for (let i = 0; i < batchSize; i++) {
            const hash = await sha256(inputPrefix + ':' + nonce);
            iterations++;

            if (hash.startsWith(target)) {
              self.postMessage({
                found: true,
                nonce,
                hash,
                iterations,
                duration: performance.now() - startTime
              });
              return;
            }
            nonce += stride;
          }

          self.postMessage({
            found: false,
            progress: iterations,
            elapsed: performance.now() - startTime
          });
        }
      };
    `;

    const blob = new Blob([workerCode], { type: 'application/javascript' });
    return new Worker(URL.createObjectURL(blob));
  }

  /** Use half of hardwareConcurrency, leaving headroom for the page. */
  private _threadCount(): number {
    const hc = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 1;
    return Math.max(1, Math.floor(hc / 2));
  }

  private _terminateWorkers(): void {
    for (const w of this.workers) {
      try {
        w.terminate();
      } catch {
        /* ignore */
      }
    }
    this.workers = [];
  }

  async fetchChallenge(siteKey?: string | null): Promise<Challenge> {
    const serverUrl = getServerUrl();
    if (!serverUrl) {
      return this._generateLocalChallenge();
    }

    try {
      const response = await fetch(
        `${serverUrl}/api/pow/challenge?siteKey=${encodeURIComponent(siteKey || 'default')}`,
      );
      if (!response.ok) {
        console.warn(`PoW challenge fetch failed (status ${response.status}), using local challenge`);
        return this._generateLocalChallenge();
      }
      this.challenge = (await response.json()) as Challenge;
      return this.challenge;
    } catch (e) {
      console.warn('PoW challenge fetch failed, using local challenge:', e);
      return this._generateLocalChallenge();
    }
  }

  private _generateLocalChallenge(): Challenge {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    this.challenge = {
      challengeId: id,
      prefix: `${id}:${Date.now()}:4`,
      difficulty: 4,
      expiresAt: Date.now() + 300000,
      local: true,
    };
    return this.challenge;
  }

  /** Solve without signals binding (legacy). */
  async startSolving(siteKey?: string | null): Promise<PoWSolution> {
    return this._solve(siteKey, null);
  }

  /** Solve with a signals hash bound into the PoW input. */
  async solveWithSignalsHash(siteKey: string | null | undefined, signalsHash: string): Promise<PoWSolution> {
    return this._solve(siteKey, signalsHash);
  }

  private async _solve(siteKey: string | null | undefined, signalsHash: string | null): Promise<PoWSolution> {
    if (this.solving && this.solvePromise) return this.solvePromise;

    if (!this.challenge) {
      await this.fetchChallenge(siteKey);
    }
    const challenge = this.challenge!;

    this.solving = true;
    this.startTime = performance.now();

    this.solvePromise = new Promise<PoWSolution>((resolve, reject) => {
      const threads = this._threadCount();
      let settled = false;

      const finish = <T>(fn: (value: T) => void, value: T): void => {
        if (settled) return;
        settled = true;
        this.solving = false;
        this._terminateWorkers();
        fn(value);
      };

      for (let i = 0; i < threads; i++) {
        const worker = this._createWorker();

        worker.onmessage = (e: MessageEvent) => {
          if (e.data.found) {
            // Report the winning worker's iteration count (not the cross-worker
            // sum) so iterations/duration matches the per-thread hash rate that
            // server-side timing detection expects.
            this.solution = {
              challengeId: challenge.challengeId,
              nonce: e.data.nonce,
              hash: e.data.hash,
              iterations: e.data.iterations,
              duration: e.data.duration,
              difficulty: challenge.difficulty,
              signalsHash: signalsHash || null,
              local: challenge.local || false,
            };
            finish(resolve, this.solution);
          }
        };

        worker.onerror = (e: ErrorEvent) => {
          finish(reject, e);
        };

        worker.postMessage({
          prefix: challenge.prefix,
          difficulty: challenge.difficulty,
          signalsHash: signalsHash || null,
          startNonce: i,
          stride: threads,
          batchSize: 5000,
        });

        this.workers.push(worker);
      }
    });

    return this.solvePromise;
  }

  async getSolution(siteKey?: string | null): Promise<PoWSolution> {
    if (this.solution) return this.solution;
    if (this.solving && this.solvePromise) return this.solvePromise;
    return this.startSolving(siteKey);
  }

  reset(): void {
    this._terminateWorkers();
    this.challenge = null;
    this.solution = null;
    this.solving = false;
    this.solvePromise = null;
  }
}

let globalPoWManager: PoWManager | null = null;

export function getPoWManager(): PoWManager {
  if (!globalPoWManager) {
    globalPoWManager = new PoWManager();
  }
  return globalPoWManager;
}
