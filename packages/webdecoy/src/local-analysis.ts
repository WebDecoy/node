/**
 * Local Analysis Module
 * Performs lightweight bot detection checks on the client side
 */

import { LocalAnalysis, RequestMetadata } from './types';

/**
 * Known datacenter IP ranges (CIDR notation)
 * These are commonly used by cloud providers and hosting services
 */
const DATACENTER_RANGES = [
  // AWS
  '3.0.0.0/8',
  '13.0.0.0/8',
  '18.0.0.0/8',
  '52.0.0.0/8',
  '54.0.0.0/8',

  // Google Cloud
  '34.0.0.0/8',
  '35.0.0.0/8',

  // Azure
  '13.64.0.0/11',
  '20.0.0.0/8',
  '40.0.0.0/8',
  '104.0.0.0/8',

  // DigitalOcean
  '159.65.0.0/16',
  '178.62.0.0/16',

  // Hetzner
  '88.99.0.0/16',
  '116.203.0.0/16',
];

/**
 * Suspicious header patterns that indicate bot behavior
 */
const SUSPICIOUS_PATTERNS = {
  userAgents: [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python/i,
    /java/i,
    /go-http-client/i,
    /axios/i,
    /okhttp/i,
  ],
  missingHeaders: [
    'accept',
    'accept-language',
    'accept-encoding',
  ],
};

/**
 * Check if an IP address is in a given CIDR range
 */
function isIPInRange(ip: string, cidr: string): boolean {
  const ipParts = ip.split('.').map(Number);
  const [range, bits] = cidr.split('/');
  const rangeParts = range.split('.').map(Number);
  const mask = ~(2 ** (32 - parseInt(bits)) - 1);

  const ipNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
  const rangeNum = (rangeParts[0] << 24) + (rangeParts[1] << 16) + (rangeParts[2] << 8) + rangeParts[3];

  return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Check if IP is from a known datacenter
 */
function isDatacenterIP(ip: string): boolean {
  // Skip IPv6 for now
  if (ip.includes(':')) {
    return false;
  }

  return DATACENTER_RANGES.some((range) => isIPInRange(ip, range));
}

/**
 * Check for suspicious headers
 */
function hasSuspiciousHeaders(metadata: RequestMetadata): boolean {
  const userAgent = metadata.user_agent || '';
  const headers = metadata.headers || {};

  // Check for bot-like user agents
  const hasBotUA = SUSPICIOUS_PATTERNS.userAgents.some((pattern) => pattern.test(userAgent));

  // Check for missing common browser headers
  const missingCommonHeaders = SUSPICIOUS_PATTERNS.missingHeaders.filter(
    (header) => !headers[header] && !headers[header.toLowerCase()]
  );

  return hasBotUA || missingCommonHeaders.length > 0;
}

/**
 * Check if Sec-CH-UA header is missing
 * Modern browsers send this header, so its absence is suspicious
 */
function isMissingSecCHUA(metadata: RequestMetadata): boolean {
  const headers = metadata.headers || {};
  return !headers['sec-ch-ua'] && !headers['Sec-CH-UA'];
}

/**
 * Calculate a local threat score (0-100)
 */
function calculateLocalScore(
  suspiciousHeaders: boolean,
  missingSecCHUA: boolean,
  datacenterIP: boolean
): number {
  let score = 0;

  if (suspiciousHeaders) score += 30;
  if (missingSecCHUA) score += 20;
  if (datacenterIP) score += 40;

  return Math.min(score, 100);
}

/**
 * Determine if server-side verification is needed
 */
function needsVerification(localScore: number, hasTLSInfo: boolean): boolean {
  // Always verify if we have TLS info (for fingerprinting)
  if (hasTLSInfo) {
    return true;
  }

  // Verify if local score is moderate to high
  return localScore >= 30;
}

/**
 * Build detection flags array
 */
function buildFlags(
  suspiciousHeaders: boolean,
  missingSecCHUA: boolean,
  datacenterIP: boolean,
  metadata: RequestMetadata
): string[] {
  const flags: string[] = [];

  if (suspiciousHeaders) {
    flags.push('suspicious_headers');
  }

  if (missingSecCHUA) {
    flags.push('missing_sec_ch_ua');
  }

  if (datacenterIP) {
    flags.push('datacenter_ip');
  }

  // Check for empty or minimal headers
  const headerCount = Object.keys(metadata.headers || {}).length;
  if (headerCount < 5) {
    flags.push('minimal_headers');
  }

  // Check for missing referer (common in automated requests)
  if (!metadata.headers?.referer && !metadata.headers?.Referer) {
    flags.push('missing_referer');
  }

  return flags;
}

/**
 * Perform local analysis on the request
 * This is a lightweight check that runs before sending to the server
 */
export function analyzeRequest(metadata: RequestMetadata): LocalAnalysis {
  const suspiciousHeaders = hasSuspiciousHeaders(metadata);
  const missingSecCHUA = isMissingSecCHUA(metadata);
  const datacenterIP = isDatacenterIP(metadata.ip);

  const localScore = calculateLocalScore(suspiciousHeaders, missingSecCHUA, datacenterIP);
  const hasTLSInfo = Boolean(metadata.tls_info);
  const needsVerify = needsVerification(localScore, hasTLSInfo);
  const flags = buildFlags(suspiciousHeaders, missingSecCHUA, datacenterIP, metadata);

  return {
    suspicious_headers: suspiciousHeaders,
    missing_sec_ch_ua: missingSecCHUA,
    datacenter_ip: datacenterIP,
    local_score: localScore,
    needs_verification: needsVerify,
    flags,
  };
}
