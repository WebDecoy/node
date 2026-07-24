/**
 * Honeytoken generator (F4 — deception layer)
 *
 * Produces a hidden decoy link and the tripwire path it points at. Embed the
 * link in a page (it is visually hidden and marked nofollow/aria-hidden, so a
 * real user never sees or clicks it); register the path with a {@link
 * TripwireRule}. Any client that parses the HTML and follows links — i.e. a
 * scraper/crawler — requests the path and is deterministically flagged, while
 * genuine users are never affected.
 */

import { randomHex } from '../webcrypto';

export interface HoneytokenOptions {
  /** Base path under which honeytoken tripwires are generated. Default `/__wd`. */
  basePath?: string;
  /** Fixed token (else a random one is generated). */
  token?: string;
  /** Visually-hidden link text. Default `.`. */
  text?: string;
}

export interface Honeytoken {
  /** The tripwire path to register with a TripwireRule (`tripwire({ paths: [token.path] })`). */
  path: string;
  /** Invisible `<a>` HTML to embed in a page; only a link-following bot requests `path`. */
  linkHtml: string;
}

/**
 * Generate a honeytoken (hidden link + tripwire path).
 *
 * @example
 * ```typescript
 * import { honeytoken, tripwire, WebDecoy } from '@webdecoy/node';
 * const hp = honeytoken();
 * const sdk = new WebDecoy({ rules: [tripwire({ paths: [hp.path] })] });
 * // ...inject hp.linkHtml into your page's HTML
 * ```
 */
export function honeytoken(options: HoneytokenOptions = {}): Honeytoken {
  const base = (options.basePath ?? '/__wd').replace(/\/+$/, '');
  const token = options.token ?? randomHex(6);
  const path = `${base}/${token}`;
  const text = options.text ?? '.';
  const linkHtml =
    `<a href="${path}" aria-hidden="true" tabindex="-1" rel="nofollow noindex" ` +
    `style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden">${text}</a>`;
  return { path, linkHtml };
}
