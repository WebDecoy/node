/**
 * In-memory stores backing the stateful detectors (fingerprint correlation and
 * rate abuse). Ported from FCaptcha index.js.
 *
 * These are defined behind interfaces so Phase 2 can swap in a shared/Redis
 * backend for serverless and multi-instance deployments.
 */

/** Tracks fingerprint ↔ IP relationships to spot distributed attacks. */
export interface FingerprintStore {
  record(fp: string, ip: string, siteKey: string): void;
  /** Number of distinct fingerprints seen from `ip`. */
  getIpFpCount(ip: string): number;
  /** Number of distinct IPs that produced fingerprint `fp` for `siteKey`. */
  getFpIpCount(fp: string, siteKey: string): number;
}

/** Sliding-window request counter. */
export interface RateLimiter {
  /** Returns `[exceeded, count]` for the window, recording this hit. */
  check(key: string, windowSeconds?: number, maxRequests?: number): [boolean, number];
}

export class InMemoryFingerprintStore implements FingerprintStore {
  private fingerprints = new Map<string, { count: number; ips: Set<string> }>();
  private ipFingerprints = new Map<string, Set<string>>();

  record(fp: string, ip: string, siteKey: string): void {
    const key = `${siteKey}:${fp}`;
    let data = this.fingerprints.get(key);
    if (!data) {
      data = { count: 0, ips: new Set() };
      this.fingerprints.set(key, data);
    }
    data.count++;
    data.ips.add(ip);

    let ipSet = this.ipFingerprints.get(ip);
    if (!ipSet) {
      ipSet = new Set();
      this.ipFingerprints.set(ip, ipSet);
    }
    ipSet.add(fp);
  }

  getIpFpCount(ip: string): number {
    return this.ipFingerprints.get(ip)?.size ?? 0;
  }

  getFpIpCount(fp: string, siteKey: string): number {
    return this.fingerprints.get(`${siteKey}:${fp}`)?.ips.size ?? 0;
  }
}

export class InMemoryRateLimiter implements RateLimiter {
  private requests = new Map<string, number[]>();

  check(key: string, windowSeconds = 60, maxRequests = 10): [boolean, number] {
    const now = Date.now();
    const cutoff = now - windowSeconds * 1000;

    const timestamps = (this.requests.get(key) ?? []).filter((t) => t > cutoff);

    const count = timestamps.length;
    if (count >= maxRequests) {
      this.requests.set(key, timestamps);
      return [true, count];
    }

    timestamps.push(now);
    this.requests.set(key, timestamps);
    return [false, count + 1];
  }
}
