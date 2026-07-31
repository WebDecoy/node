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

// Honeytoken (#482). A helper rather than automatic injection — see the module
// for why Next middleware cannot rewrite a streamed RSC response.
export { honeytokenLink } from './honeytoken';
export type { SiteHoneytoken } from './honeytoken';

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
