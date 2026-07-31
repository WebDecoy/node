/**
 * Site honeytoken — a stable, derivable trap the adapters can inject for you
 *.
 *
 * WHY THIS EXISTS ALONGSIDE honeytoken()
 *
 * `honeytoken()` mints a RANDOM path per call. That is fine when a developer
 * holds the returned object and wires both halves themselves, and useless for
 * automatic injection: the adapter would advertise a different path on every
 * request, and on a second replica the tripwire armed there would not match the
 * link served here. A crawler that followed the bait would trip nothing.
 *
 * So the token is DERIVED, exactly as the WordPress plugin derives it: HMAC of a
 * label under a per-site secret. Every process with the same secret computes the
 * same path without coordinating, and nothing extra is stored.
 *
 * WHY THIS MATTERS AT ALL
 *
 * A trap hit is the only detection in this product that needs no score, no
 * JavaScript, no fingerprint and no IP — the client asked for a path that exists
 * nowhere and is linked only from an element no human can see.
 *
 * That is not a stylistic preference, it is arithmetic. Honeypot hits carry the
 * highest weight in the threat score and a User-Agent carries nearly none,
 * because a User-Agent is trivially spoofed — so the same client scores near
 * zero on a page view and very high on a trap.
 *
 * Which only pays off if the link is on the page. Generating a token and asking
 * the developer to place it is a step most installs never take, so the adapters
 * that own the response inject it themselves.
 */

import { hmacSha256Hex } from '../webcrypto';

/** Base path for honeytoken tripwires. Mirrors the WordPress plugin. */
export const HONEYTOKEN_BASE_PATH = '/__wd';

/** Token length in hex chars, matching the plugin and `randomHex(6)`. */
const TOKEN_LEN = 12;

export interface SiteHoneytokenOptions {
  /**
   * Secret the token is derived from. Must be stable across every process
   * serving the site, or replicas advertise paths each other has not armed.
   * The SDK passes the API key, which is already exactly that.
   */
  secret: string;
  /** Base path. Default `/__wd`. */
  basePath?: string;
  /**
   * Rotate the token daily, keeping yesterday's armed as a grace window.
   *
   * Off by default. Rotation is only safe when every armed path is served from
   * the same clock, and a page cached by a CDN can outlive the grace window —
   * at which point the trap silently stops catching anything, which is worse
   * than a static path a determined attacker could eventually notice.
   */
  rotate?: boolean;
  /** Visually-hidden link text. Default `.`. */
  text?: string;
}

/**
 * The link as data rather than markup, so a JSX or template caller can render an
 * anchor directly instead of reaching for `dangerouslySetInnerHTML`. Same
 * attributes as `linkHtml`, which stays for string-templating environments.
 */
export interface HoneytokenLinkProps {
  href: string;
  rel: string;
  tabIndex: number;
  'aria-hidden': 'true';
  style: Record<string, string>;
  text: string;
}

export interface SiteHoneytoken {
  /** The path advertised in the injected link. */
  primaryPath: string;
  /**
   * Every path that must be armed as a tripwire right now — today and
   * yesterday when rotating, so a crawler part-way through a crawl still trips.
   */
  activePaths: string[];
  /** The hidden `<a>` to inject, for string-templating environments. */
  linkHtml: string;
  /** The same link as props, for JSX — avoids innerHTML entirely. */
  linkProps: HoneytokenLinkProps;
}

function utcDay(offsetDays = 0): string {
  const d = new Date(Date.now() + offsetDays * 86_400_000);
  return d.toISOString().slice(0, 10);
}

function escapeHtml(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * The hidden link markup.
 *
 * Byte-for-byte the same hiding technique as `honeytoken()` and the WordPress
 * plugin, so behaviour matches across SDKs.
 *
 * Every attribute is load-bearing and none is decoration:
 *
 *   - `rel="nofollow noindex"` and off-screen positioning mean a robots-honouring
 *     crawler will not follow it. A trap that catches Googlebot is a bug, not a
 *     detection — it would file the customer's own search traffic as an attack.
 *   - `aria-hidden` and `tabindex="-1"` keep it out of the accessibility tree and
 *     the tab order, so a screen-reader or keyboard user cannot reach it. Without
 *     these this feature is an accessibility defect that punishes the user for
 *     using assistive technology.
 */
function linkFor(path: string, text: string): string {
  // `text` is caller-supplied config. It has no business containing markup, but
  // it flows straight into a page, and "it's only our own config" is how config
  // ends up templated from a database field two refactors later.
  text = escapeHtml(text);
  return (
    `<a href="${path}" aria-hidden="true" tabindex="-1" rel="nofollow noindex" ` +
    `style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">${text}</a>`
  );
}

const HIDDEN_STYLE: Record<string, string> = {
  position: 'absolute',
  left: '-9999px',
  top: 'auto',
  width: '1px',
  height: '1px',
  overflow: 'hidden',
};

function propsFor(path: string, text: string): HoneytokenLinkProps {
  return {
    href: path,
    rel: 'nofollow noindex',
    tabIndex: -1,
    'aria-hidden': 'true',
    style: HIDDEN_STYLE,
    text,
  };
}

/**
 * Derive the site's honeytoken.
 *
 * Async because the derivation is WebCrypto HMAC, which keeps this usable on
 * edge runtimes where `node:crypto` does not exist. Callers are expected to
 * resolve it once and reuse the result.
 */
export async function siteHoneytoken(
  options: SiteHoneytokenOptions,
): Promise<SiteHoneytoken> {
  const base = (options.basePath ?? HONEYTOKEN_BASE_PATH).replace(/\/+$/, '');
  const text = options.text ?? '.';

  const derive = async (label: string): Promise<string> =>
    `${base}/${(await hmacSha256Hex(options.secret, label)).slice(0, TOKEN_LEN)}`;

  if (!options.rotate) {
    const path = await derive('stable');
    return {
      primaryPath: path,
      activePaths: [path],
      linkHtml: linkFor(path, text),
      linkProps: propsFor(path, text),
    };
  }

  const today = await derive(`day:${utcDay(0)}`);
  const yesterday = await derive(`day:${utcDay(-1)}`);
  return {
    primaryPath: today,
    // Yesterday stays armed so a crawler that read the page before midnight and
    // follows the link after it still trips.
    activePaths: Array.from(new Set([today, yesterday])),
    linkHtml: linkFor(today, text),
    linkProps: propsFor(today, text),
  };
}

/**
 * Insert the hidden link into an HTML document.
 *
 * Returns the input unchanged when there is nowhere sensible to put it, which is
 * the correct outcome for a fragment, a JSON body mislabelled as HTML, or a
 * document that already carries the link.
 *
 * Injection targets `</body>` and falls back to `</html>`. It deliberately does
 * NOT append to arbitrary markup: putting an anchor after `</html>` is invalid,
 * and some parsers relocate it in ways that could make it visible — a visible
 * trap catches customers, not crawlers.
 */
export function injectHoneytokenLink(html: string, linkHtml: string): string {
  if (!html || html.includes(linkHtml)) return html;

  const lower = html.toLowerCase();
  for (const close of ['</body>', '</html>']) {
    const at = lower.lastIndexOf(close);
    if (at !== -1) {
      return html.slice(0, at) + linkHtml + html.slice(at);
    }
  }
  return html;
}

/**
 * Whether a response's content type is a full HTML document we may rewrite.
 *
 * Anything else is left alone: JSON, streams, images, downloads. Injecting an
 * anchor into a JSON body would corrupt it, and corrupting a customer's API
 * response is a far worse failure than a missed detection.
 */
export function isInjectableHtml(contentType: string | undefined | null): boolean {
  if (!contentType) return false;
  return contentType.toLowerCase().split(';')[0].trim() === 'text/html';
}
