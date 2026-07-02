import { honeytoken } from './honeytoken';

// These tests back the README's zero-false-positive claim: the decoy link must
// be invisible to real users and marked so well-behaved crawlers don't follow
// or index it. Only a link-following scraper that ignores these signals hits it.
describe('honeytoken', () => {
  it('marks the decoy link nofollow + noindex', () => {
    expect(honeytoken().linkHtml).toContain('rel="nofollow noindex"');
  });

  it('hides the link from real users (a11y + visually offscreen)', () => {
    const { linkHtml } = honeytoken();
    expect(linkHtml).toContain('aria-hidden="true"');
    expect(linkHtml).toContain('tabindex="-1"');
    expect(linkHtml).toMatch(/position:\s*absolute/);
    expect(linkHtml).toContain('left:-9999px');
    expect(linkHtml).toMatch(/width:\s*1px/);
    expect(linkHtml).toMatch(/height:\s*1px/);
    expect(linkHtml).toMatch(/overflow:\s*hidden/);
  });

  it('points the link at the tripwire path it returns', () => {
    const hp = honeytoken();
    expect(hp.linkHtml).toContain(`href="${hp.path}"`);
  });

  it('defaults the path under /__wd and honours a custom basePath', () => {
    expect(honeytoken().path).toMatch(/^\/__wd\/[a-f0-9]+$/);
    expect(honeytoken({ basePath: '/trap' }).path).toMatch(/^\/trap\/[a-f0-9]+$/);
    // trailing slashes are normalized
    expect(honeytoken({ basePath: '/trap/' }).path).toMatch(/^\/trap\/[a-f0-9]+$/);
  });

  it('generates a unique token per call', () => {
    expect(honeytoken().path).not.toBe(honeytoken().path);
  });

  it('honours a fixed token and custom link text', () => {
    const hp = honeytoken({ token: 'abc123', text: 'x' });
    expect(hp.path).toBe('/__wd/abc123');
    expect(hp.linkHtml).toContain('>x</a>');
  });
});
