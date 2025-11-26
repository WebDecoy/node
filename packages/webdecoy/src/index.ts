/**
 * Web Decoy SDK for Node.js
 *
 * Advanced bot detection with TLS fingerprinting
 *
 * @example
 * ```typescript
 * import { WebDecoy } from '@webdecoy/node';
 *
 * const webdecoy = new WebDecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY,
 * });
 *
 * const result = await webdecoy.protect({
 *   method: req.method,
 *   path: req.path,
 *   ip: req.ip,
 *   user_agent: req.headers['user-agent'],
 *   headers: req.headers,
 *   timestamp: Date.now(),
 * });
 *
 * if (!result.allowed) {
 *   return res.status(403).json({ error: 'Access denied' });
 * }
 * ```
 */

export { WebDecoy } from './sdk';

export type {
  WebDecoyConfig,
  TLSInfo,
  RequestMetadata,
  LocalAnalysis,
  SDKDetectionRequest,
  SDKDetectionResponse,
  ProtectResult,
  ProtectOptions,
} from './types';
