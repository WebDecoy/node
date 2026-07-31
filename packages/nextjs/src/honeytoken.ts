/**
 * Honeytoken for Next.js.
 *
 * WHY THIS IS A HELPER AND NOT AUTOMATIC
 *
 * The Express adapter injects the hidden link by wrapping `res.write`/`res.end`
 * and rewriting the finished HTML. Next middleware cannot do that. It runs
 * BEFORE the route handler and returns a `NextResponse`; the App Router then
 * streams the RSC payload directly to the client. There is no complete document
 * for middleware to rewrite, and buffering a stream to synthesise one would
 * defeat streaming — trading the framework's headline feature for a hidden link.
 *
 * Partial support would be worse than none. Injecting only into the
 * non-streamed cases would give a trap that works in development and silently
 * stops working under the rendering mode most production apps use, which is the
 * failure mode this whole issue is about: a feature that looks installed and
 * detects nothing.
 *
 * So Next gets an honest one-liner instead. It is one line in the root layout,
 * and it is the same derived path the tripwire is armed on.
 *
 * Rendered from `linkProps` as ordinary JSX rather than through
 * `dangerouslySetInnerHTML`: the markup is a single anchor, so there is no
 * reason to hand React a raw HTML string and every reason not to teach that
 * habit in a snippet people will paste.
 *
 * @example
 * ```tsx
 * // app/layout.tsx
 * import { honeytokenLink } from '@webdecoy/nextjs';
 *
 * export default async function RootLayout({ children }: { children: React.ReactNode }) {
 *   const { linkProps } = await honeytokenLink(process.env.WEBDECOY_API_KEY!);
 *   const { text, ...anchor } = linkProps;
 *   return (
 *     <html>
 *       <body>
 *         {children}
 *         <a {...anchor}>{text}</a>
 *       </body>
 *     </html>
 *   );
 * }
 * ```
 *
 * Then arm it in middleware:
 *
 * ```typescript
 * import { withWebDecoy } from '@webdecoy/nextjs';
 * import { tripwire } from '@webdecoy/node';
 *
 * const bait = await honeytokenLink(process.env.WEBDECOY_API_KEY!);
 * export default withWebDecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY!,
 *   rules: [tripwire({ paths: bait.activePaths, includeDefaults: false })],
 * });
 * ```
 */

import { siteHoneytoken, type SiteHoneytoken } from '@webdecoy/node';

/**
 * Derive this site's honeytoken.
 *
 * Pass the API key: the token is an HMAC of it, so every replica and every
 * render computes the same path without coordinating. A random path would mean
 * the process that served the link and the process that armed the tripwire
 * disagree, and a crawler following the bait would trip nothing.
 *
 * Cached per secret, because a layout renders on every request and the
 * derivation is a crypto call.
 */
const cache = new Map<string, Promise<SiteHoneytoken>>();

export function honeytokenLink(
  apiKey: string,
  options: { rotate?: boolean; text?: string } = {},
): Promise<SiteHoneytoken> {
  const key = `${apiKey}|${options.rotate ? 'rot' : 'stable'}|${options.text ?? '.'}`;
  let existing = cache.get(key);
  if (!existing) {
    existing = siteHoneytoken({ secret: apiKey, ...options });
    cache.set(key, existing);
  }
  return existing;
}

export type { SiteHoneytoken } from '@webdecoy/node';
