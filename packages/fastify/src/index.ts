/**
 * Web Decoy Fastify Integration
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import webdecoy from '@webdecoy/fastify';
 *
 * const fastify = Fastify();
 *
 * fastify.register(webdecoy, {
 *   apiKey: process.env.WEBDECOY_API_KEY,
 *   skipPaths: ['/health', '/metrics'],
 * });
 *
 * fastify.get('/api/data', async (request, reply) => {
 *   // request.webdecoy contains detection info
 *   console.log('Bot detected:', request.webdecoy?.bot_detected);
 *   return { data: 'protected' };
 * });
 * ```
 */

export { default, webdecoyPlugin } from './plugin';
export type { WebDecoyPluginOptions } from './plugin';

// Self-hosted captcha endpoints (PoW + detection + tokens)
export { webdecoyCaptchaPlugin } from './captcha';
export type { CaptchaEndpointsOptions } from '@webdecoy/node';

// Re-export core types for convenience
export type {
  WebDecoyConfig,
  RequestMetadata,
  SDKDetectionResponse,
  ProtectResult,
} from '@webdecoy/node';
