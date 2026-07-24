/**
 * Web Decoy API Client
 * Handles communication with the ingest service.
 *
 * Uses the Web-standard `fetch` API (no axios, no `node:` imports) so the SDK
 * runs in Node >= 18 and edge runtimes (Vercel Edge Middleware, Cloudflare
 * Workers) alike.
 */

import { SDKDetectionRequest, SDKDetectionResponse } from './types';
import type { ViolationEvent, IPEnrichmentData } from './rules/types';

export interface ClientConfig {
  apiKey: string;
  apiUrl: string;
  timeout: number;
  debug: boolean;
  /**
   * Kept for API compatibility; the fetch transport does not support disabling
   * TLS verification. For local self-signed certs in Node, trust the CA
   * instead: `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.
   */
  tlsRejectUnauthorized: boolean;
}

interface ApiErrorBody {
  error?: string;
  message?: string;
}

interface ApiResponse<T> {
  status: number;
  data: T | undefined;
}

export class WebDecoyClient {
  private config: ClientConfig;
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor(config: ClientConfig) {
    this.config = config;
    this.baseUrl = config.apiUrl.replace(/\/+$/, '');
    this.headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`,
      'User-Agent': 'webdecoy-node-sdk/0.1.0',
    };

    if (config.tlsRejectUnauthorized === false && config.debug) {
      console.warn(
        '[WebDecoy] tlsRejectUnauthorized=false is not supported by the fetch transport and is ignored; ' +
          'for local self-signed certs, trust your CA via NODE_EXTRA_CA_CERTS=/path/to/ca.pem.',
      );
    }
  }

  private async request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<ApiResponse<T>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeout);
    // Node returns a Timeout object that would otherwise hold the process open;
    // edge runtimes return a number with no unref.
    if (typeof (timer as { unref?: () => void }).unref === 'function') {
      (timer as unknown as { unref: () => void }).unref();
    }

    if (this.config.debug) {
      console.log('[WebDecoy] Request:', { method, url: this.baseUrl + path, data: body });
    }

    try {
      const response = await fetch(this.baseUrl + path, {
        method,
        headers: this.headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });

      let data: T | undefined;
      const text = await response.text();
      if (text) {
        try {
          data = JSON.parse(text) as T;
        } catch {
          data = undefined;
        }
      }

      if (this.config.debug) {
        console.log('[WebDecoy] Response:', { status: response.status, data });
      }

      return { status: response.status, data };
    } catch (error) {
      if (this.config.debug) {
        console.error('[WebDecoy] Error:', {
          message: error instanceof Error ? error.message : String(error),
        });
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Send a detection request to the ingest service
   */
  async detect(request: SDKDetectionRequest): Promise<SDKDetectionResponse> {
    let response: ApiResponse<SDKDetectionResponse & ApiErrorBody>;
    try {
      response = await this.request<SDKDetectionResponse & ApiErrorBody>(
        'POST',
        '/api/v1/sdk/detect',
        request,
      );
    } catch (error) {
      if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
        throw new Error('Request timeout. The Web Decoy service did not respond in time.');
      }
      if (error instanceof TypeError) {
        // fetch signals DNS/connection failures as TypeError
        throw new Error('Unable to connect to Web Decoy service. Please check your network.');
      }
      throw error;
    }

    if (response.status === 401) {
      throw new Error('Invalid API key. Please check your Web Decoy configuration.');
    }

    if (response.status === 429) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }

    if (response.status >= 400) {
      if (response.data?.error || response.data?.message) {
        throw new Error(response.data.error || response.data.message || 'API error');
      }
      throw new Error(`API request failed: HTTP ${response.status}`);
    }

    return response.data as SDKDetectionResponse;
  }

  /**
   * Send violation events to the ingest service
   */
  async sendViolations(events: ViolationEvent[]): Promise<void> {
    try {
      await this.request('POST', '/api/v1/sdk/violations/batch', { events });
    } catch (error) {
      if (this.config.debug) {
        console.error('[WebDecoy] Failed to send violations:', error);
      }
      // Silently fail — violations are best-effort
    }
  }

  /**
   * Get IP enrichment data from the ingest service
   */
  async getIPEnrichment(ip: string): Promise<IPEnrichmentData | null> {
    try {
      const response = await this.request<IPEnrichmentData>(
        'GET',
        `/api/v1/sdk/ip/${encodeURIComponent(ip)}/enrichment`,
      );
      if (response.status >= 400) return null;
      return response.data ?? null;
    } catch (error) {
      if (this.config.debug) {
        console.error('[WebDecoy] Failed to get IP enrichment:', error);
      }
      return null;
    }
  }

  /**
   * Validate the API key by making a test request
   */
  async validateAPIKey(): Promise<boolean> {
    try {
      // Send a minimal detection request to validate the key
      const testRequest: SDKDetectionRequest = {
        request_metadata: {
          method: 'GET',
          path: '/__webdecoy_test__',
          ip: '127.0.0.1',
          headers: {},
          timestamp: Date.now(),
        },
        local_analysis: {
          suspicious_headers: false,
          missing_sec_ch_ua: false,
          datacenter_ip: false,
          local_score: 0,
          needs_verification: false,
          flags: ['api_key_validation'],
        },
      };

      await this.detect(testRequest);
      return true;
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid API key')) {
        return false;
      }
      // Other errors might be network-related, consider the key valid
      return true;
    }
  }
}
