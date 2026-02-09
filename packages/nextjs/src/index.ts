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

// Re-export core types for convenience
export type {
  WebDecoyConfig,
  RequestMetadata,
  SDKDetectionResponse,
  ProtectResult,
} from '@webdecoy/node';
