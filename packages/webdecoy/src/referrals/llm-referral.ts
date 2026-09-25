/**
 * Recognises a visit an AI product sent: a Referer from an AI chat or search
 * platform, or, when the browser sent no Referer, a campaign tag naming one.
 *
 * The platform table is generated from WebDecoy's own classifier, and this is
 * a port of that classifier, pinned case for case by generated golden vectors
 * (llm-referral.test.ts), so the SDK counts exactly what the dashboard's other
 * sensors count.
 */
import { LLM_PLATFORMS } from './llm-platforms.generated';

/** Campaign parameters that can name an AI product, in precedence order. */
const TAG_KEYS = ['utm_source', 'ref', 'utm_medium'] as const;

/**
 * The platform a referral came from, or '' when it is not an AI referral. A
 * non-empty Referer decides on its own even when it names no AI product: a
 * campaign tag is easy to forge and must not overrule what the browser sent.
 */
export function classifyReferral(referer: string | undefined, pageUrl: string): string {
  const ref = (referer ?? '').trim();
  if (ref) {
    try {
      return LLM_PLATFORMS[new URL(ref).hostname.toLowerCase()] ?? '';
    } catch {
      return '';
    }
  }
  let url: URL;
  try {
    url = new URL(pageUrl);
  } catch {
    return '';
  }
  for (const key of TAG_KEYS) {
    for (const value of url.searchParams.getAll(key)) {
      const platform = platformForTag(value);
      if (platform) return platform;
    }
  }
  return '';
}

const squash = (s: string): string => s.replace(/[ \-_.]/g, '');

function platformForTag(raw: string): string {
  let value = raw.trim().toLowerCase();
  if (!value) return '';
  try {
    const host = new URL(value).hostname;
    if (host) value = host.toLowerCase();
  } catch {
    // Not a URL: a bare domain or a name, both handled below.
  }
  value = value.replace(/\.$/, '');
  if (LLM_PLATFORMS[value]) return LLM_PLATFORMS[value];
  const normalized = squash(value);
  for (const [domain, name] of Object.entries(LLM_PLATFORMS)) {
    if (normalized === squash(name.toLowerCase()) || normalized === domain.replace(/^www\./, '').replace(/\./g, '')) {
      return name;
    }
  }
  return '';
}
