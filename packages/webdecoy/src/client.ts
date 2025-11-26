/**
 * Web Decoy API Client
 * Handles communication with the ingest service
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { SDKDetectionRequest, SDKDetectionResponse } from './types';

export interface ClientConfig {
  apiKey: string;
  apiUrl: string;
  timeout: number;
  debug: boolean;
}

export class WebDecoyClient {
  private axios: AxiosInstance;
  private config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = config;

    this.axios = axios.create({
      baseURL: config.apiUrl,
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.apiKey}`,
        'User-Agent': 'webdecoy-node-sdk/0.1.0',
      },
    });

    // Add request interceptor for debugging
    if (config.debug) {
      this.axios.interceptors.request.use((request) => {
        console.log('[WebDecoy] Request:', {
          method: request.method,
          url: request.url,
          data: request.data,
        });
        return request;
      });

      this.axios.interceptors.response.use(
        (response) => {
          console.log('[WebDecoy] Response:', {
            status: response.status,
            data: response.data,
          });
          return response;
        },
        (error) => {
          console.error('[WebDecoy] Error:', {
            message: error.message,
            response: error.response?.data,
          });
          return Promise.reject(error);
        }
      );
    }
  }

  /**
   * Send a detection request to the ingest service
   */
  async detect(request: SDKDetectionRequest): Promise<SDKDetectionResponse> {
    try {
      const response = await this.axios.post<SDKDetectionResponse>(
        '/api/v1/sdk/detect',
        request
      );

      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError<{ error?: string; message?: string }>;

        // Handle specific error cases
        if (axiosError.response?.status === 401) {
          throw new Error('Invalid API key. Please check your Web Decoy configuration.');
        }

        if (axiosError.response?.status === 429) {
          throw new Error('Rate limit exceeded. Please try again later.');
        }

        if (axiosError.response?.data?.error || axiosError.response?.data?.message) {
          throw new Error(
            axiosError.response.data.error || axiosError.response.data.message || 'API error'
          );
        }

        // Network or timeout errors
        if (axiosError.code === 'ECONNABORTED') {
          throw new Error('Request timeout. The Web Decoy service did not respond in time.');
        }

        if (axiosError.code === 'ENOTFOUND' || axiosError.code === 'ECONNREFUSED') {
          throw new Error('Unable to connect to Web Decoy service. Please check your network.');
        }

        throw new Error(`API request failed: ${axiosError.message}`);
      }

      // Unknown error
      throw error;
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
