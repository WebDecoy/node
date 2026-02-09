/**
 * IP Enrichment Client
 * Fetches and caches IP enrichment data from the WebDecoy API
 */

import type { WebDecoyClient } from './client';
import type { IPEnrichmentData } from './rules/types';

interface CachedEntry {
  data: IPEnrichmentData;
  expiresAt: number;
}

export class IPEnrichmentClient {
  private client: WebDecoyClient;
  private cache = new Map<string, CachedEntry>();
  private ttlMs: number;
  private pending = new Map<string, Promise<IPEnrichmentData | null>>();

  constructor(client: WebDecoyClient, ttlMs = 3600_000) {
    this.client = client;
    this.ttlMs = ttlMs;
  }

  /**
   * Get enrichment data for an IP address.
   * Returns cached data if available (1h TTL), otherwise fetches from API.
   * Returns null if enrichment fails (fail-open).
   */
  async enrich(ip: string): Promise<IPEnrichmentData | null> {
    // Check cache
    const cached = this.cache.get(ip);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.data;
    }

    // Deduplicate concurrent requests for the same IP
    const inflight = this.pending.get(ip);
    if (inflight) {
      return inflight;
    }

    const promise = this.fetchAndCache(ip);
    this.pending.set(ip, promise);

    try {
      return await promise;
    } finally {
      this.pending.delete(ip);
    }
  }

  private async fetchAndCache(ip: string): Promise<IPEnrichmentData | null> {
    const data = await this.client.getIPEnrichment(ip);

    if (data) {
      this.cache.set(ip, {
        data,
        expiresAt: Date.now() + this.ttlMs,
      });
    }

    return data;
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}
