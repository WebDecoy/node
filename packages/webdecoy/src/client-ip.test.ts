import { resolveClientIp, normalizeIp, ipInCidr } from './client-ip';

/** A Node-style header bag. */
const h = (headers: Record<string, string | string[]>) => headers;

/** A WHATWG Headers, as the edge adapters pass. */
const web = (headers: Record<string, string>) => new Headers(headers);

describe('normalizeIp', () => {
  it.each([
    ['203.0.113.9', '203.0.113.9'],
    ['  203.0.113.9  ', '203.0.113.9'],
    ['203.0.113.9:44321', '203.0.113.9'],
    ['[2001:db8::1]:8080', '2001:db8::1'],
    ['[2001:db8::1]', '2001:db8::1'],
    ['2001:DB8::1', '2001:db8::1'],
    ['fe80::1%eth0', 'fe80::1'],
    ['::1', '::1'],
    ['::', '::'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeIp(input)).toBe(expected);
  });

  it('collapses IPv4-mapped IPv6 so a dual-stack listener keys the same client once', () => {
    expect(normalizeIp('::ffff:203.0.113.9')).toBe('203.0.113.9');
    expect(normalizeIp('[::ffff:203.0.113.9]:443')).toBe('203.0.113.9');
  });

  it.each([
    ['', 'empty'],
    ['   ', 'whitespace'],
    ['not-an-ip', 'garbage'],
    ['203.0.113.999', 'octet out of range'],
    ['203.0.113', 'too few octets'],
    ['010.0.0.1', 'leading zero — decimal and octal readers disagree'],
    ['2001:db8::1::2', 'two :: runs'],
    ['2001:db8:::1', 'malformed run'],
    ['12345::1', 'group too long'],
    ['2001:db8:0:0:0:0:0:0:1', 'nine groups'],
    ['<script>', 'injection attempt'],
  ])('rejects %s (%s)', (input) => {
    expect(normalizeIp(input)).toBeNull();
  });

  it('rejects null and undefined', () => {
    expect(normalizeIp(null)).toBeNull();
    expect(normalizeIp(undefined)).toBeNull();
  });
});

describe('ipInCidr', () => {
  it('matches inside an IPv4 range and not outside it', () => {
    expect(ipInCidr('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(ipInCidr('11.1.2.3', '10.0.0.0/8')).toBe(false);
  });

  it('handles prefixes that fall mid-byte', () => {
    expect(ipInCidr('192.168.1.5', '192.168.0.0/23')).toBe(true);
    expect(ipInCidr('192.168.2.5', '192.168.0.0/23')).toBe(false);
  });

  it('treats a bare address as a single host', () => {
    expect(ipInCidr('203.0.113.9', '203.0.113.9')).toBe(true);
    expect(ipInCidr('203.0.113.10', '203.0.113.9')).toBe(false);
  });

  it('matches IPv6 ranges', () => {
    expect(ipInCidr('2001:db8::dead:beef', '2001:db8::/32')).toBe(true);
    expect(ipInCidr('2001:db9::1', '2001:db8::/32')).toBe(false);
  });

  it('never matches across address families', () => {
    expect(ipInCidr('10.0.0.1', '::/0')).toBe(false);
    expect(ipInCidr('2001:db8::1', '0.0.0.0/0')).toBe(false);
  });

  it('rejects a nonsense prefix length rather than guessing', () => {
    expect(ipInCidr('10.0.0.1', '10.0.0.0/33')).toBe(false);
    expect(ipInCidr('10.0.0.1', '10.0.0.0/abc')).toBe(false);
    expect(ipInCidr('10.0.0.1', '10.0.0.0/')).toBe(false);
  });
});

describe('resolveClientIp', () => {
  describe('the default: believe no forwarding header', () => {
    it('uses the peer address and ignores a forged chain', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4' }),
        peer: '198.51.100.7',
      });
      expect(ip).toBe('198.51.100.7');
    });

    it('is what an attacker cannot move — this is the regression', () => {
      // Before the fix this returned 1.2.3.4 and the caller got a fresh
      // rate-limit bucket per forged address.
      const forged = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4' }),
        peer: '198.51.100.7',
      });
      const alsoForged = resolveClientIp({
        headers: h({ 'x-forwarded-for': '5.6.7.8' }),
        peer: '198.51.100.7',
      });
      expect(forged).toBe(alsoForged);
    });

    it('returns undefined when there is no peer and nothing is trusted', () => {
      expect(resolveClientIp({ headers: h({ 'x-forwarded-for': '1.2.3.4' }) })).toBeUndefined();
    });

    it('treats trustProxy: 0 as the same thing', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4' }),
        peer: '198.51.100.7',
        trustProxy: 0,
      });
      expect(ip).toBe('198.51.100.7');
    });
  });

  describe('a number of trusted hops', () => {
    it('takes the rightmost entry for one proxy', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4, 203.0.113.9' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('takes the second from the right for two', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4, 203.0.113.9, 10.0.0.5' }),
        peer: '10.0.0.1',
        trustProxy: 2,
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('a client prepending entries cannot shift the answer', () => {
      const honest = resolveClientIp({
        headers: h({ 'x-forwarded-for': '203.0.113.9' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      const padded = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 203.0.113.9' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(honest).toBe('203.0.113.9');
      expect(padded).toBe('203.0.113.9');
    });

    it('falls back to the peer when the chain is shorter than the configured depth', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '203.0.113.9' }),
        peer: '10.0.0.1',
        trustProxy: 3,
      });
      expect(ip).toBe('10.0.0.1');
    });

    it('falls back to the peer when the header is absent', () => {
      const ip = resolveClientIp({ headers: h({}), peer: '10.0.0.1', trustProxy: 1 });
      expect(ip).toBe('10.0.0.1');
    });

    it('falls back to the peer when the selected entry is malformed', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '203.0.113.9, not-an-ip' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(ip).toBe('10.0.0.1');
    });

    it('joins a repeated header before splitting it', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': ['1.2.3.4', '203.0.113.9'] }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('ignores a negative or fractional depth rather than indexing with it', () => {
      const opts = { headers: h({ 'x-forwarded-for': '1.2.3.4' }), peer: '10.0.0.1' };
      expect(resolveClientIp({ ...opts, trustProxy: -1 })).toBe('10.0.0.1');
      expect(resolveClientIp({ ...opts, trustProxy: 1.5 })).toBe('10.0.0.1');
    });
  });

  describe('cloudflare', () => {
    it('reads CF-Connecting-IP', () => {
      const ip = resolveClientIp({
        headers: h({ 'cf-connecting-ip': '203.0.113.9', 'x-forwarded-for': '1.2.3.4' }),
        peer: '10.0.0.1',
        trustProxy: 'cloudflare',
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('falls back to the peer when the header is missing or junk', () => {
      expect(
        resolveClientIp({ headers: h({}), peer: '10.0.0.1', trustProxy: 'cloudflare' }),
      ).toBe('10.0.0.1');
      expect(
        resolveClientIp({
          headers: h({ 'cf-connecting-ip': 'nope' }),
          peer: '10.0.0.1',
          trustProxy: 'cloudflare',
        }),
      ).toBe('10.0.0.1');
    });
  });

  describe('a CIDR list', () => {
    const trustProxy = ['10.0.0.0/8', '172.16.0.0/12'];

    it('walks past our proxies to the first address that is not ours', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '203.0.113.9, 10.0.0.5' }),
        peer: '10.0.0.1',
        trustProxy,
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('stops at the innermost untrusted hop, however deep the chain claims to be', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 203.0.113.9, 172.16.0.2, 10.0.0.5' }),
        peer: '10.0.0.1',
        trustProxy,
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('returns the peer when the peer itself is not one of ours', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '1.2.3.4' }),
        peer: '198.51.100.7',
        trustProxy,
      });
      expect(ip).toBe('198.51.100.7');
    });

    it('stops at a malformed entry instead of believing what is left of it', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '203.0.113.9, junk, 10.0.0.5' }),
        peer: '10.0.0.1',
        trustProxy,
      });
      expect(ip).toBe('10.0.0.1');
    });

    it('returns the outermost entry when every hop is ours', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '10.0.0.9, 10.0.0.5' }),
        peer: '10.0.0.1',
        trustProxy,
      });
      expect(ip).toBe('10.0.0.9');
    });
  });

  describe('IPv6 and header shapes', () => {
    it('resolves an IPv6 client through a trusted hop', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '2001:db8::dead:beef' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(ip).toBe('2001:db8::dead:beef');
    });

    it('strips the port some proxies append to a bracketed IPv6 entry', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': '[2001:db8::1]:53124' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(ip).toBe('2001:db8::1');
    });

    it('reads a WHATWG Headers the same way', () => {
      const ip = resolveClientIp({
        headers: web({ 'x-forwarded-for': '1.2.3.4, 203.0.113.9' }),
        trustProxy: 1,
      });
      expect(ip).toBe('203.0.113.9');
    });

    it('tolerates the empty entries a chained proxy can leave behind', () => {
      const ip = resolveClientIp({
        headers: h({ 'x-forwarded-for': ' , 203.0.113.9 ,' }),
        peer: '10.0.0.1',
        trustProxy: 1,
      });
      expect(ip).toBe('203.0.113.9');
    });
  });
});
