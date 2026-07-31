/**
 * The edge validator's verdict, as the origin sees it.
 *
 * WHY THIS MODULE EXISTS
 *
 * The Cloudflare clearance worker has set `x-wd-clearance` on every forwarded
 * request since the validator shipped, and nothing has ever read it. Grepping the
 * header across the monorepo, this SDK and the WordPress plugin returned only the
 * worker that writes it, its own tests, and one documentation page. We shipped a
 * tag no customer could act on, then documented it as "watch the header in your
 * logs."
 *
 * That gap matters more than it sounds. On a scoped route the gate's only options
 * were pass or challenge, and a challenge on public content is a 403 to every
 * client that cannot run JavaScript — search crawlers included. Reading the tag
 * gives the application a third option it owns: log it, meter it, skip an
 * expensive query, serve something cheaper. That is the first "yes" a cautious
 * operator can give.
 *
 * WHAT IT IS NOT
 *
 * These values are advisory context, not authentication. They are only meaningful
 * for requests that actually passed through the edge validator, and the validator
 * strips inbound copies precisely so that the origin can attribute them to us.
 * A request that reaches the origin WITHOUT passing through the proxy — straight
 * to the origin IP, or a route that does not match — can carry anything. Treat
 * `present: false` as "no information", never as "not a bot", and keep the origin
 * unreachable except through the proxy if you intend to branch on this.
 */

/** Header the edge validator uses for its clearance verdict. */
export const EDGE_CLEARANCE_HEADER = 'x-wd-clearance';

/** Header the edge validator uses for the sensor's client classification. */
export const EDGE_CLASS_HEADER = 'x-wd-class';

/**
 * What the edge sensor concluded the client is.
 *
 * - `verified` — an identity something other than the client has attested
 *   (Cloudflare's verified-bot signal). **Never degrade these.** This is
 *   Googlebot and friends, and quietly serving them less is how a customer loses
 *   search presence and blames you six weeks later.
 * - `crawler` — self-declares as a crawler, unproven. Real-but-unverified
 *   crawlers and forged ones both land here.
 * - `script` — an HTTP client library, a Chromium user agent sending no client
 *   hints, or no user agent at all. Not a browser.
 * - `browser` — nothing that distinguishes a non-human fired. A statement about
 *   our signals, not a certificate.
 */
export type EdgeClass = 'verified' | 'crawler' | 'script' | 'browser';

const EDGE_CLASSES: readonly EdgeClass[] = ['verified', 'crawler', 'script', 'browser'];

/**
 * The edge's annotations on one request, typed.
 *
 * Every field is optional except `present`, because the edge validator may not be
 * in front of this request at all — and the difference between "the edge said
 * browser" and "there is no edge here" is the difference between a safe
 * optimisation and a security hole.
 */
export interface EdgeVerdict {
  /**
   * True when the edge validator annotated this request. False means no
   * information — not "human", not "safe".
   */
  present: boolean;

  /**
   * The clearance verdict, e.g. `valid`, `missing`, `verified-bot`,
   * `signed-agent`, `machine`, `insufficient-trust`. Free-form on purpose: the
   * validator gains labels faster than an SDK release can enumerate them, and an
   * unknown label must not become `undefined`.
   */
  clearance?: string;

  /** The sensor's classification, when it classified this request. */
  class?: EdgeClass;

  /** `class === 'verified'`. Convenience so callers need no string literals. */
  isVerified: boolean;
  /** `class === 'crawler'`. */
  isCrawler: boolean;
  /** `class === 'script'`. */
  isScript: boolean;
  /** `class === 'browser'`. */
  isBrowser: boolean;

  /**
   * True for a class that is not a browser and is not attested — `script` or
   * `crawler`.
   *
   * This is the predicate most applications actually want, and it deliberately
   * excludes `verified`: the common intent is "cheapen this response", and the one
   * population you must never cheapen for is the one whose identity was proven.
   */
  isUnattestedNonBrowser: boolean;
}

/** The verdict for a request the edge never touched. */
function absent(): EdgeVerdict {
  return {
    present: false,
    isVerified: false,
    isCrawler: false,
    isScript: false,
    isBrowser: false,
    isUnattestedNonBrowser: false,
  };
}

function normaliseClass(raw: string | undefined): EdgeClass | undefined {
  if (!raw) return undefined;
  const v = raw.trim().toLowerCase();
  return (EDGE_CLASSES as readonly string[]).includes(v) ? (v as EdgeClass) : undefined;
}

/**
 * Read the edge validator's annotations out of a request's headers.
 *
 * Accepts the header bag the SDK already carries on `RequestMetadata` — lowercase
 * keys — and tolerates mixed case, since adapters differ on normalisation.
 *
 * An unrecognised class value is dropped rather than passed through. The set is
 * closed and small; a value outside it means either a version skew or something
 * that is not our worker, and in both cases silence beats a value a caller might
 * branch on.
 */
export function readEdgeVerdict(headers: Record<string, string> | undefined): EdgeVerdict {
  if (!headers) return absent();

  let clearanceRaw: string | undefined;
  let classRaw: string | undefined;
  for (const key of Object.keys(headers)) {
    const k = key.toLowerCase();
    if (k === EDGE_CLEARANCE_HEADER) clearanceRaw = headers[key];
    else if (k === EDGE_CLASS_HEADER) classRaw = headers[key];
  }

  const clearance = clearanceRaw?.trim() || undefined;
  const cls = normaliseClass(classRaw);

  if (!clearance && !cls) return absent();

  return {
    present: true,
    clearance,
    class: cls,
    isVerified: cls === 'verified',
    isCrawler: cls === 'crawler',
    isScript: cls === 'script',
    isBrowser: cls === 'browser',
    isUnattestedNonBrowser: cls === 'script' || cls === 'crawler',
  };
}
