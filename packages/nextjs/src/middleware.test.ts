import { NextRequest } from 'next/server';
import { withWebDecoy } from './middleware';
import { getEdgeVerdict } from './edge-verdict';

/**
 * The Next.js adapter's annotation, and the edge tag it has to let through (#481).
 *
 * This adapter shipped a bug that made the feature it advertised impossible: it
 * set its annotation with `response.headers.set()` after `NextResponse.next()`,
 * which writes RESPONSE headers. The application — route handlers, server
 * components — reads REQUEST headers, so it never saw the annotation at all, and
 * the visitor we had just judged received our decision and detection id.
 *
 * These tests assert both halves of the fix, in the only terms that matter: what
 * the application receives, and what the browser receives.
 */

/**
 * Next.js exposes forwarded request headers on the middleware response as
 * `x-middleware-override-headers` plus one `x-middleware-request-<name>` per
 * header. That encoding is how `NextResponse.next({ request })` reaches the app,
 * so reading it here is how we assert the app would see the header — asserting on
 * `response.headers` alone is precisely the mistake that shipped.
 */
function forwardedToApp(res: Response, name: string): string | null {
  return res.headers.get(`x-middleware-request-${name}`);
}

function req(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('https://shop.example/products', { headers });
}

/** Config with no API key and no rules: protect() fails open locally, no network. */
const OPTIONS = { skipLocalAnalysis: true } as const;

describe('withWebDecoy annotates the request, not the response', () => {
  it('does not put its annotation on the response, where the browser would see it', async () => {
    const res = await withWebDecoy({ ...OPTIONS })(req());
    // The visitor must not be told our decision or our detection id.
    expect(res.headers.get('x-webdecoy-decision')).toBeNull();
    expect(res.headers.get('x-webdecoy-detection-id')).toBeNull();
  });

  it('forwards the edge tag through to the application untouched', async () => {
    // The tag the Cloudflare validator set upstream has to survive this middleware
    // — it is the whole point of #481 that the application can read it.
    const res = await withWebDecoy({ ...OPTIONS })(
      req({ 'x-wd-class': 'script', 'x-wd-clearance': 'valid' })
    );
    expect(forwardedToApp(res, 'x-wd-class')).toBe('script');
    expect(forwardedToApp(res, 'x-wd-clearance')).toBe('valid');
    // And it is still not echoed to the browser.
    expect(res.headers.get('x-wd-class')).toBeNull();
  });

  it('an inbound copy of its own annotation never reaches the application', async () => {
    // An application trusting x-webdecoy-decision must not be talkable-into by the
    // request being judged.
    //
    // What guarantees this is that every protect() path returns a detection, so the
    // annotation is always written over the client's. The explicit delete in the
    // middleware is insurance for the day `detection` becomes optional — this test
    // asserts the property, not the mechanism, because the property is what a
    // customer depends on.
    //
    // The forged values are deliberately ones the SDK cannot produce. An earlier
    // draft forged `decision: allow`, which is exactly what the fail-open path
    // legitimately writes, so it passed for the wrong reason.
    const res = await withWebDecoy({ ...OPTIONS })(
      req({
        'x-webdecoy-decision': 'trust-me-i-am-a-browser',
        'x-webdecoy-detection-id': 'forged-by-the-client',
      })
    );
    expect(forwardedToApp(res, 'x-webdecoy-decision')).not.toBe('trust-me-i-am-a-browser');
    expect(forwardedToApp(res, 'x-webdecoy-detection-id')).not.toBe('forged-by-the-client');
  });

  it('skipPaths still short-circuits', async () => {
    const res = await withWebDecoy({ ...OPTIONS, skipPaths: ['/products'] })(req());
    expect(res.status).toBe(200);
  });
});

describe('getEdgeVerdict', () => {
  it('reads the tag from a plain Request in a route handler', () => {
    const edge = getEdgeVerdict(new Request('https://shop.example/api/search', {
      headers: { 'x-wd-class': 'script', 'x-wd-clearance': 'missing' },
    }));
    expect(edge.present).toBe(true);
    expect(edge.isScript).toBe(true);
    expect(edge.clearance).toBe('missing');
  });

  it('reads the tag from a Headers object', () => {
    const edge = getEdgeVerdict(new Headers({ 'x-wd-class': 'verified' }));
    expect(edge.isVerified).toBe(true);
    // Never cheapen a response for an attested identity.
    expect(edge.isUnattestedNonBrowser).toBe(false);
  });

  it('reports no edge as no information', () => {
    const edge = getEdgeVerdict(new Request('https://shop.example/api/search'));
    expect(edge.present).toBe(false);
    expect(edge.isBrowser).toBe(false);
  });
});
