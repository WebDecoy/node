/**
 * Resolving the client IP address behind a proxy.
 *
 * WHY THIS MODULE EXISTS
 *
 * Every adapter used to read the leftmost value of `X-Forwarded-For` and call it
 * the client. That header is written by the client for the first hop, so the
 * leftmost value is whatever the caller decided to put there. One
 * `-H 'X-Forwarded-For: 1.2.3.4'` gave an attacker a fresh rate-limit bucket per
 * forged address, put an address of their choosing on every violation we
 * reported, and made `filter({ expression: 'ip.tor' })` an opt-in check.
 *
 * A forwarding header is only evidence if you know who wrote it. So the default
 * here is to not read one at all: use the address the connection actually came
 * from, and make the operator say how many proxies sit in front before we
 * believe anything else. The WordPress plugin already works this way; this
 * brings the Node adapters in line.
 *
 * THE MODEL
 *
 * Each proxy appends the address it received the connection from, so the
 * observed chain outermost-first is `[...X-Forwarded-For, peer]` and the entries
 * to the RIGHT are the ones added by infrastructure you control. Trust is
 * therefore counted from the right: with one proxy in front of you, the client
 * is the last `X-Forwarded-For` entry; with two, the second from last. Anything
 * further left was supplied by someone you have no reason to believe.
 *
 * No `node:net` — this runs in Edge and Workers runtimes too, so the address
 * parsing is hand-rolled and covered by tests.
 */

/**
 * How much of the forwarding chain to believe.
 *
 * - `false` (default) — read no forwarding headers; the peer address is the
 *   client. Correct for an app exposed directly, and safe for one that isn't:
 *   it attributes traffic to your proxy rather than to a forged address.
 * - `number` — the number of trusted proxies between the client and this
 *   process. The client is the Nth entry from the right of `X-Forwarded-For`.
 * - `'cloudflare'` — use `CF-Connecting-IP`. Only meaningful if the origin is
 *   unreachable except through Cloudflare, since the header is otherwise just
 *   another thing a client can send.
 * - `string[]` — CIDRs (or bare addresses) of the proxies you run. The chain is
 *   walked right to left and the first address that isn't one of yours is the
 *   client. Use this when the depth varies.
 */
export type TrustedProxies = false | number | 'cloudflare' | string[];

/** Headers as either a Node-style bag or a WHATWG `Headers`. */
export type HeaderSource =
  | Record<string, string | string[] | undefined>
  | { get(name: string): string | null };

export interface ResolveClientIpOptions {
  /** Request headers. */
  headers: HeaderSource;
  /** The address the connection came from, when the runtime exposes one. */
  peer?: string;
  /** How much of the forwarding chain to believe. Defaults to `false`. */
  trustProxy?: TrustedProxies;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * A dotted quad as four bytes, or null.
 *
 * Leading zeros are rejected rather than parsed: `010.0.0.1` means one thing to
 * a decimal parser and another to anything that reads it as octal, and an
 * address that two parsers disagree about is not an address we should key
 * anything on.
 */
function ipv4ToBytes(ip: string): Uint8Array | null {
  const m = IPV4.exec(ip);
  if (!m) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = m[i + 1];
    if (part.length > 1 && part[0] === '0') return null;
    const n = Number(part);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

/** An IPv6 address as sixteen bytes, or null. Handles `::` and an IPv4 tail. */
function ipv6ToBytes(input: string): Uint8Array | null {
  let s = input.toLowerCase();

  // An embedded IPv4 tail (`::ffff:1.2.3.4`) is folded into the two hex groups
  // it stands for, so the rest of the parse only ever sees hex groups.
  const lastColon = s.lastIndexOf(':');
  if (lastColon !== -1 && s.slice(lastColon + 1).includes('.')) {
    const tail = ipv4ToBytes(s.slice(lastColon + 1));
    if (!tail) return null;
    const g1 = ((tail[0] << 8) | tail[1]).toString(16);
    const g2 = ((tail[2] << 8) | tail[3]).toString(16);
    s = `${s.slice(0, lastColon + 1)}${g1}:${g2}`;
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const groups = part.split(':');
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  const head = parseGroups(halves[0]);
  if (head === null) return null;

  let groups: number[];
  if (halves.length === 2) {
    const tail = parseGroups(halves[1]);
    if (tail === null) return null;
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = groups[i] >> 8;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}

function ipToBytes(ip: string): Uint8Array | null {
  return ipv4ToBytes(ip) ?? ipv6ToBytes(ip);
}

/**
 * Strip the decoration real-world sources add to an address — brackets, a port,
 * an IPv6 zone id — and return it in a canonical form, or null if what's left
 * isn't an address at all.
 *
 * IPv4-mapped IPv6 (`::ffff:203.0.113.9`) collapses to the IPv4 form, so a
 * dual-stack listener and an `X-Forwarded-For` entry for the same client
 * produce the same key.
 */
export function normalizeIp(raw: string | undefined | null): string | null {
  if (!raw) return null;
  let v = raw.trim();
  if (!v) return null;

  if (v.startsWith('[')) {
    // "[::1]:8080" or "[::1]"
    const close = v.indexOf(']');
    if (close === -1) return null;
    v = v.slice(1, close);
  } else if (v.includes('.') && v.split(':').length === 2) {
    // "203.0.113.9:44321" — an unbracketed IPv6 always has more than one colon.
    v = v.slice(0, v.indexOf(':'));
  }

  const pct = v.indexOf('%');
  if (pct !== -1) v = v.slice(0, pct);

  if (ipv4ToBytes(v)) return v;

  const bytes = ipv6ToBytes(v);
  if (!bytes) return null;

  const mapped =
    bytes.subarray(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  if (mapped) return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;

  return v.toLowerCase();
}

/**
 * Whether an address falls inside a CIDR range. A bare address is treated as a
 * single-host range. Families never match across each other.
 */
export function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf('/');
  const network = normalizeIp(slash === -1 ? cidr : cidr.slice(0, slash));
  const address = normalizeIp(ip);
  if (!network || !address) return false;

  const netBytes = ipToBytes(network);
  const addrBytes = ipToBytes(address);
  if (!netBytes || !addrBytes || netBytes.length !== addrBytes.length) return false;

  const totalBits = netBytes.length * 8;
  let bits = totalBits;
  if (slash !== -1) {
    const raw = cidr.slice(slash + 1);
    bits = Number(raw);
    if (raw === '' || !Number.isInteger(bits) || bits < 0 || bits > totalBits) return false;
  }

  const wholeBytes = bits >> 3;
  for (let i = 0; i < wholeBytes; i++) {
    if (netBytes[i] !== addrBytes[i]) return false;
  }
  const remainder = bits & 7;
  if (remainder) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    if ((netBytes[wholeBytes] & mask) !== (addrBytes[wholeBytes] & mask)) return false;
  }
  return true;
}

function readHeader(headers: HeaderSource, name: string): string | undefined {
  if (typeof (headers as { get?: unknown }).get === 'function') {
    return (headers as { get(n: string): string | null }).get(name) ?? undefined;
  }
  const bag = headers as Record<string, string | string[] | undefined>;
  const value = bag[name] ?? bag[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(',');
  return value;
}

/**
 * The `X-Forwarded-For` chain, outermost first. Entries that don't parse as an
 * address are kept as `null` so a caller can tell "nothing there" from "someone
 * put junk in the chain" — the two deserve different answers.
 */
function forwardedChain(headers: HeaderSource): (string | null)[] {
  const raw = readHeader(headers, 'x-forwarded-for');
  if (!raw) return [];
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
    .map((part) => normalizeIp(part));
}

/**
 * Resolve the client IP for a request.
 *
 * Returns `undefined` only when there is nothing to go on: no peer address and
 * no header the configuration says to believe. Callers supply their own last
 * resort, because what that should be is a per-framework question.
 *
 * Whenever the configured source is missing or malformed this falls back to the
 * peer address rather than reaching further left in the chain. The peer is the
 * one address on a request that cannot be forged, so a wrong-but-real proxy
 * address beats a plausible-looking value the caller chose.
 */
export function resolveClientIp(options: ResolveClientIpOptions): string | undefined {
  const { headers, trustProxy = false } = options;
  const peer = normalizeIp(options.peer) ?? undefined;

  if (trustProxy === false || trustProxy === 0) return peer;

  if (trustProxy === 'cloudflare') {
    return normalizeIp(readHeader(headers, 'cf-connecting-ip')) ?? peer;
  }

  const chain = forwardedChain(headers);

  if (typeof trustProxy === 'number') {
    if (!Number.isInteger(trustProxy) || trustProxy < 0) return peer;
    // The client is the Nth entry from the right. A chain shorter than the
    // configured depth means the request did not arrive the way the operator
    // described it, so we believe none of it.
    const index = chain.length - trustProxy;
    if (index < 0 || index >= chain.length) return peer;
    return chain[index] ?? peer;
  }

  // CIDR list: walk right to left, past addresses that belong to us. `peer`
  // sits at the right-hand end because it is the innermost hop we can see.
  const full: (string | null)[] = peer ? [...chain, peer] : [...chain];
  for (let i = full.length - 1; i >= 0; i--) {
    const candidate = full[i];
    // A malformed entry stops the walk: we cannot tell whether it is ours, so
    // nothing to its left is evidence.
    if (candidate === null) return peer;
    if (!trustProxy.some((range) => ipInCidr(candidate, range))) return candidate;
  }
  // Every hop was trusted, which means the outermost one is as far as the chain
  // goes — that address is the client.
  return (full[0] ?? undefined) ?? peer;
}
