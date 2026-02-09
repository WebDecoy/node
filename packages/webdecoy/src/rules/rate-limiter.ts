/**
 * In-Memory Rate Limiter
 * Provides fixed window and sliding window rate limiting algorithms
 */

interface FixedWindowEntry {
  count: number;
  windowStart: number;
}

/**
 * In-memory rate limiter with automatic cleanup
 */
export class InMemoryRateLimiter {
  private fixedWindows = new Map<string, FixedWindowEntry>();
  private slidingWindows = new Map<string, number[]>();
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor() {
    // Clean up expired entries every 60 seconds
    this.cleanupTimer = setInterval(() => this.cleanup(), 60_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Check and increment for fixed window algorithm
   * Returns the current count after increment, and the window reset time
   */
  checkFixedWindow(
    key: string,
    max: number,
    windowMs: number,
  ): { allowed: boolean; current: number; resetAt: number } {
    const now = Date.now();
    const entry = this.fixedWindows.get(key);

    if (!entry || now - entry.windowStart >= windowMs) {
      // New window
      this.fixedWindows.set(key, { count: 1, windowStart: now });
      return { allowed: true, current: 1, resetAt: now + windowMs };
    }

    entry.count++;
    const resetAt = entry.windowStart + windowMs;

    if (entry.count > max) {
      return { allowed: false, current: entry.count, resetAt };
    }

    return { allowed: true, current: entry.count, resetAt };
  }

  /**
   * Check and increment for sliding window algorithm
   * Returns the current count after adding the new timestamp
   */
  checkSlidingWindow(
    key: string,
    max: number,
    windowMs: number,
  ): { allowed: boolean; current: number; resetAt: number } {
    const now = Date.now();
    const cutoff = now - windowMs;

    let timestamps = this.slidingWindows.get(key);
    if (!timestamps) {
      timestamps = [];
      this.slidingWindows.set(key, timestamps);
    }

    // Remove expired timestamps
    while (timestamps.length > 0 && timestamps[0] <= cutoff) {
      timestamps.shift();
    }

    // Add current timestamp
    timestamps.push(now);

    const resetAt = timestamps.length > 0 ? timestamps[0] + windowMs : now + windowMs;

    if (timestamps.length > max) {
      return { allowed: false, current: timestamps.length, resetAt };
    }

    return { allowed: true, current: timestamps.length, resetAt };
  }

  /**
   * Clean up expired entries from both maps
   */
  private cleanup(): void {
    const now = Date.now();

    // Clean fixed windows: remove entries where the window has expired
    // Use a generous 2x window to avoid removing entries too aggressively
    for (const [key, entry] of this.fixedWindows) {
      if (now - entry.windowStart > 300_000) {
        // 5 minutes stale
        this.fixedWindows.delete(key);
      }
    }

    // Clean sliding windows: remove entries with no recent timestamps
    for (const [key, timestamps] of this.slidingWindows) {
      if (timestamps.length === 0) {
        this.slidingWindows.delete(key);
        continue;
      }
      const latest = timestamps[timestamps.length - 1];
      if (now - latest > 300_000) {
        // 5 minutes stale
        this.slidingWindows.delete(key);
      }
    }
  }

  /**
   * Release resources
   */
  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.fixedWindows.clear();
    this.slidingWindows.clear();
  }
}
