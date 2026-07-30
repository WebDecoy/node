/**
 * Web Decoy Next.js Integration
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { withWebDecoy } from '@webdecoy/nextjs';
 *
 * export default withWebDecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY!,
 * });
 *
 * export const config = {
 *   matcher: ['/api/:path*', '/protected/:path*'],
 * };
 * ```
 */

export { withWebDecoy, withBotProtection } from './middleware';
export type { WebDecoyMiddlewareOptions, WithBotProtectionOptions } from './middleware';

// The edge validator's verdict, readable from a route handler or server
// component — not only from middleware (#481).
export { getEdgeVerdict } from './edge-verdict';
export type { EdgeVerdict, EdgeClass } from './edge-verdict';

// Self-hosted captcha route handlers (PoW + detection + tokens)
export { createCaptchaHandler } from './captcha';
export type { NextCaptchaHandlers } from './captcha';
export type { CaptchaEndpointsOptions } from '@webdecoy/node';

// Re-export core types for convenience
export type {
  WebDecoyConfig,
  RequestMetadata,
  SDKDetectionResponse,
  ProtectResult,
} from '@webdecoy/node';
