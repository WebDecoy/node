import { ruleBlockResponse, shouldSkipPath, type BlockResponse } from './adapter-core';
import { normalizeIp, resolveClientIp, type TrustedProxies } from './client-ip';
import type { Decision } from './decision';
import { WebDecoy } from './sdk';
import type { ProtectOptions, RequestMetadata, WebDecoyConfig } from './types';

export interface NodeHttpGuardOptions extends WebDecoyConfig, ProtectOptions {
  /** Monitor serves the request even when the SDK reports a denial. */
  mode?: 'monitor' | 'enforce';
  /** Paths excluded from evaluation, such as health checks. */
  skipPaths?: (string | RegExp)[];
  /** Defaults to the connection peer. Set this to trust a known proxy chain. */
  trustProxy?: TrustedProxies;
}

export interface NodeHttpGuardOutcome {
  decision: Decision;
  /** Present when enforce mode refuses the request. The caller writes it. */
  response?: BlockResponse;
}

/** The request fields read from Node's IncomingMessage. */
export interface NodeHttpRequest {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string };
}

export interface NodeHttpGuard {
  sdk: WebDecoy;
  /** Evaluate a request without reading its body. Skipped paths return undefined. */
  check(request: NodeHttpRequest): Promise<NodeHttpGuardOutcome | undefined>;
}

/** Evaluate native Node HTTP requests with the same rules as the framework adapters. */
export function createNodeHttpGuard(options: NodeHttpGuardOptions = {}): NodeHttpGuard {
  const sdk = new WebDecoy(options);
  const mode = options.mode ?? 'monitor';
  const protectOptions: ProtectOptions = {
    threshold: options.threshold,
    skipLocalAnalysis: options.skipLocalAnalysis,
    metadata: options.metadata,
  };

  return {
    sdk,
    async check(request) {
      // Strip an absolute-form authority without changing the raw path encoding.
      const target = (request.url ?? '/').replace(/^https?:\/\/[^/?#]+/i, '');
      const queryStart = target.indexOf('?');
      const path = (queryStart === -1 ? target : target.slice(0, queryStart)) || '/';
      const query = queryStart === -1 ? undefined : target.slice(queryStart + 1);
      if (shouldSkipPath(path, options.skipPaths)) return undefined;

      const headers: Record<string, string> = Object.create(null);
      for (const [name, value] of Object.entries(request.headers)) {
        if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(', ') : value;
      }
      const peer = request.socket.remoteAddress;
      const metadata: RequestMetadata = {
        method: request.method ?? 'GET',
        path,
        query,
        headers,
        user_agent: headers['user-agent'],
        ip:
          resolveClientIp({ headers, peer, trustProxy: options.trustProxy }) ??
          normalizeIp(peer) ??
          '127.0.0.1',
        timestamp: Date.now(),
      };

      const decision = await sdk.protect(metadata, protectOptions);
      if (decision.allowed || mode !== 'enforce') return { decision };

      const block = ruleBlockResponse(decision) ?? {
        status: 403,
        headers: {},
        body: { error: 'Forbidden', message: 'Access denied by WebDecoy protection' },
      };
      return {
        decision,
        response: {
          status: block.status,
          headers: { 'content-type': 'application/json', ...block.headers },
          body: { ...block.body, detection_id: decision.id },
        },
      };
    },
  };
}
