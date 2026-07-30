import {
  siteHoneytoken,
  injectHoneytokenLink,
  isInjectableHtml,
  HONEYTOKEN_BASE_PATH,
} from './honeytoken-site';

/**
 * The site honeytoken (#482).
 *
 * `sdk_tripwire` had FOUR rows in production, ever, because the SDK generated a
 * honeytoken and asked the developer to embed it. This is the half that lets an
 * adapter do it — which needs the path to be DERIVED rather than random, so
 * every replica computes the same one.
 */
describe('siteHoneytoken', () => {
  it('derives the same path from the same secret, in any process', async () => {
    const a = await siteHoneytoken({ secret: 'sk_live_example' });
    const b = await siteHoneytoken({ secret: 'sk_live_example' });
    expect(a.primaryPath).toBe(b.primaryPath);
    // The whole reason this is not honeytoken(): a random path would mean the
    // replica that served the link and the replica that armed the tripwire
    // disagree, and a crawler following the bait trips nothing.
    expect(a.primaryPath).toMatch(new RegExp(`^${HONEYTOKEN_BASE_PATH}/[0-9a-f]{12}$`));
  });

  it('a different secret is a different trap', async () => {
    const a = await siteHoneytoken({ secret: 'site-one' });
    const b = await siteHoneytoken({ secret: 'site-two' });
    expect(a.primaryPath).not.toBe(b.primaryPath);
  });

  it('arms exactly the path it advertises', async () => {
    const t = await siteHoneytoken({ secret: 's' });
    expect(t.activePaths).toContain(t.primaryPath);
    expect(t.linkHtml).toContain(`href="${t.primaryPath}"`);
  });

  it('rotating keeps yesterday armed but advertises today', async () => {
    const t = await siteHoneytoken({ secret: 's', rotate: true });
    expect(t.activePaths).toHaveLength(2);
    expect(t.activePaths[0]).toBe(t.primaryPath);
    // A crawler that read the page before midnight and follows the link after it
    // must still trip, or rotation silently turns the trap off once a day.
    expect(t.activePaths[1]).not.toBe(t.primaryPath);
  });

  /**
   * Every attribute here is load-bearing. Their absence turns this feature into
   * an SEO defect and an accessibility defect at the same time.
   */
  it('is invisible to crawlers that honour robots and to assistive tech', async () => {
    const { linkHtml } = await siteHoneytoken({ secret: 's' });
    // A trap that catches Googlebot files the customer's own search traffic as
    // an attack.
    expect(linkHtml).toContain('rel="nofollow noindex"');
    // Reachable by a screen reader or the tab key would punish the user for
    // using assistive technology.
    expect(linkHtml).toContain('aria-hidden="true"');
    expect(linkHtml).toContain('tabindex="-1"');
    expect(linkHtml).toContain('left:-9999px');
  });
});

describe('injectHoneytokenLink', () => {
  const link = '<a href="/__wd/abc">.</a>';

  it('injects before </body>', () => {
    expect(injectHoneytokenLink('<html><body><p>hi</p></body></html>', link)).toBe(
      `<html><body><p>hi</p>${link}</body></html>`,
    );
  });

  it('falls back to </html> when there is no body', () => {
    expect(injectHoneytokenLink('<html><p>hi</p></html>', link)).toBe(
      `<html><p>hi</p>${link}</html>`,
    );
  });

  it('injects once, not once per render', () => {
    const once = injectHoneytokenLink('<body>x</body>', link);
    expect(injectHoneytokenLink(once, link)).toBe(once);
  });

  it('leaves a fragment alone rather than appending loose markup', () => {
    // An anchor after </html> is invalid, and some parsers relocate it — which
    // could make the trap visible. A visible trap catches customers.
    const fragment = '<div>partial</div>';
    expect(injectHoneytokenLink(fragment, link)).toBe(fragment);
  });

  it('handles an empty body', () => {
    expect(injectHoneytokenLink('', link)).toBe('');
  });

  it('is case-insensitive about the closing tag', () => {
    expect(injectHoneytokenLink('<HTML><BODY>x</BODY></HTML>', link)).toContain(link);
  });
});

describe('isInjectableHtml', () => {
  it('accepts full HTML documents', () => {
    expect(isInjectableHtml('text/html')).toBe(true);
    expect(isInjectableHtml('text/html; charset=utf-8')).toBe(true);
    expect(isInjectableHtml('TEXT/HTML')).toBe(true);
  });

  it('refuses everything else', () => {
    // Injecting an anchor into JSON corrupts a customer's API response, which is
    // a far worse failure than a missed detection.
    for (const ct of [
      'application/json',
      'text/plain',
      'image/png',
      'application/xhtml+xml',
      'text/event-stream',
      undefined,
      '',
    ]) {
      expect(isInjectableHtml(ct)).toBe(false);
    }
  });
});

/**
 * `text` is caller config, but it flows straight into a page. "It's only our own
 * config" is how a value ends up templated from a database field two refactors
 * later, so it is escaped at the boundary.
 */
describe('link text is escaped', () => {
  it('cannot inject markup through the text option', async () => {
    const t = await siteHoneytoken({
      secret: 's',
      text: '</a><script>alert(1)</script>',
    });
    expect(t.linkHtml).not.toContain('<script>');
    expect(t.linkHtml).toContain('&lt;script&gt;');
    // Exactly one anchor: the escaped text cannot have closed ours early.
    expect(t.linkHtml.match(/<a /g)).toHaveLength(1);
  });

  it('exposes the link as props so JSX never needs innerHTML', async () => {
    const { linkProps, primaryPath } = await siteHoneytoken({ secret: 's' });
    expect(linkProps.href).toBe(primaryPath);
    expect(linkProps.rel).toBe('nofollow noindex');
    expect(linkProps.tabIndex).toBe(-1);
    expect(linkProps['aria-hidden']).toBe('true');
    expect(linkProps.style.position).toBe('absolute');
    // Raw here on purpose: JSX escapes text children itself, and double-escaping
    // would render the entities literally.
    expect(linkProps.text).toBe('.');
  });
});
