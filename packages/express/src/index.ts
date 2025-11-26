/**
 * Web Decoy Express Integration
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { webdecoy } from '@webdecoy/express';
 *
 * const app = express();
 *
 * app.use(webdecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY,
 *   skipPaths: ['/health', '/api/webhook'],
 * }));
 *
 * app.get('/api/data', (req, res) => {
 *   // req.webdecoy contains detection info
 *   console.log('Bot detected:', req.webdecoy?.bot_detected);
 *   res.json({ data: 'protected' });
 * });
 * ```
 */

export { webdecoy } from './middleware';
export type { WebDecoyMiddlewareOptions } from './middleware';

// Re-export core types for convenience
export type {
  WebDecoyConfig,
  RequestMetadata,
  SDKDetectionResponse,
  ProtectResult,
} from '@webdecoy/node';
