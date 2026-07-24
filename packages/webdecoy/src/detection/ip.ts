/**
 * Datacenter IP range matching.
 *
 * Ported from FCaptcha detection.js. IPv4 only; IPv6 and richer reputation
 * (VPN/proxy/Tor, abuse score, geo) continue to be served by the remote
 * api.webdecoy.com enrichment endpoint.
 */

/** Strict dotted-quad check (no leading zeros), matching `net.isIPv4` semantics. */
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isIPv4(ip: string): boolean {
  return IPV4_RE.test(ip);
}

/** Coarse datacenter CIDR blocks (AWS, GCP, Azure, DO, Linode, Vultr, Hetzner, OVH). */
export const DATACENTER_CIDRS: string[] = [
  // AWS
  '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8',
  '52.0.0.0/8', '54.0.0.0/8', '99.0.0.0/8',
  // Google Cloud
  '34.64.0.0/10', '35.184.0.0/13', '104.154.0.0/15', '104.196.0.0/14',
  // Azure
  '13.64.0.0/11', '20.0.0.0/8', '40.64.0.0/10', '52.224.0.0/11',
  // DigitalOcean
  '64.225.0.0/16', '68.183.0.0/16', '104.131.0.0/16', '134.209.0.0/16',
  '138.68.0.0/16', '139.59.0.0/16', '142.93.0.0/16', '157.245.0.0/16',
  // Linode
  '45.33.0.0/16', '45.56.0.0/16', '45.79.0.0/16', '139.162.0.0/16',
  // Vultr
  '45.32.0.0/16', '45.63.0.0/16', '45.76.0.0/16', '108.61.0.0/16',
  // Hetzner
  '5.9.0.0/16', '46.4.0.0/14', '78.46.0.0/15', '88.99.0.0/16',
  '95.216.0.0/14', '135.181.0.0/16',
  // OVH
  '51.38.0.0/16', '51.68.0.0/16', '51.75.0.0/16', '137.74.0.0/16',
  '139.99.0.0/16', '144.217.0.0/16', '149.56.0.0/16',
];

function ipToLong(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function cidrContains(cidr: string, ip: string): boolean {
  const [range, bits] = cidr.split('/');
  const mask = (~((1 << (32 - parseInt(bits, 10))) - 1)) >>> 0;
  const rangeStart = ipToLong(range) & mask;
  const ipLong = ipToLong(ip);
  return (ipLong & mask) === rangeStart;
}

/** True when `ip` falls inside a known datacenter CIDR block (IPv4 only). */
export function isDatacenterIP(ip: string): boolean {
  if (!isIPv4(ip)) return false;
  return DATACENTER_CIDRS.some((cidr) => cidrContains(cidr, ip));
}
