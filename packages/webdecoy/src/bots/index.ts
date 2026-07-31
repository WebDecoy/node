/**
 * Local bot classification (#500).
 *
 * WHY THIS IS IN THE SDK AT ALL
 *
 * The scoring pipeline already identifies named agents server-side, but it does
 * so *after* the request is reported — which is too late to decide anything. A
 * customer who wants "block AI training crawlers, allow search crawlers" needs
 * the answer synchronously, in the request path, with no network call. So the Go
 * registry is generated into {@link BOT_REGISTRY} and matched here.
 *
 * WHAT THIS IS NOT
 *
 * This is a User-Agent lookup. It identifies agents that say who they are, and
 * nothing else. An agent that spoofs Chrome is invisible to it, and always will
 * be — that is the point of the 1% User-Agent weight in the unified score, and
 * nothing here changes that arithmetic.
 *
 * That is a feature for the use case it serves. GPTBot, ClaudeBot and Googlebot
 * all self-identify honestly, and the decision a customer wants to make about
 * them ("don't train on my content") is a POLICY choice about a cooperative
 * agent, not a threat judgement about a hostile one. Acting on a claim is
 * correct when the claim is the thing you care about.
 *
 * For agents that lie, the answer is the rest of the product: tripwires,
 * honeytokens and the edge classifier see behaviour, which cannot be spoofed by
 * editing a header.
 */

import { BOT_REGISTRY, type BotAgent, type BotCategory } from './registry.generated';

export { BOT_REGISTRY, BOT_CATEGORIES } from './registry.generated';
export type { BotAgent, BotCategory } from './registry.generated';

/**
 * Categories that are some flavour of AI client, collapsed into one flag because
 * "is this AI" is the question customers actually ask, and spelling it as a
 * four-way comparison in every rule invites getting it wrong by one.
 */
const AI_CATEGORIES: ReadonlySet<string> = new Set<BotCategory>([
  'training_crawler',
  'ai_search_crawler',
  'ai_agent',
  'ai_assistant',
]);

/**
 * What a rule sees about the agent behind a request.
 *
 * Always populated, never undefined: a rule that has to check whether
 * classification ran is a rule people get wrong. When nothing matched,
 * `known` is false and `category` is `'none'`.
 */
export interface BotVerdict {
  /** Whether the User-Agent matched a known agent. */
  known: boolean;
  /** Registry slug, e.g. `gptbot`. Undefined when unknown. */
  id?: string;
  /** Display name, e.g. `GPTBot`. Undefined when unknown. */
  name?: string;
  /** Customer-facing category — the same vocabulary as the dashboard. */
  category: BotCategory;
  /** Operator, e.g. `OpenAI`. Undefined when unknown. */
  organization?: string;
  /** The registry's threat score for this agent, 0-100. 0 when unknown. */
  score: number;
  /**
   * Whether the operator documents honouring robots.txt. Undefined when unknown.
   *
   * Documented behaviour, not observed behaviour — it is what the operator
   * publishes, so treat it as a claim like any other.
   */
  respectsRobots?: boolean;
  /** True for training crawlers, AI search crawlers, AI agents and assistants. */
  isAI: boolean;
}

const UNKNOWN: BotVerdict = Object.freeze({
  known: false,
  category: 'none' as BotCategory,
  score: 0,
  isAI: false,
});

/**
 * Cache of User-Agent -> match, because the same handful of strings repeat
 * across essentially every request and the scan is ~250 substring tests.
 *
 * BOUNDED ON PURPOSE. The key is attacker-controlled: a client sending a unique
 * User-Agent per request would otherwise grow this map without limit, turning a
 * performance optimisation into a memory-exhaustion vector. On overflow the
 * whole map is dropped rather than evicted one-by-one — it costs one rebuild of
 * a cache that refills in microseconds, and it needs no bookkeeping to get wrong.
 */
const MAX_CACHE = 1000;
const cache = new Map<string, BotAgent | null>();

/**
 * Find the agent behind a User-Agent string, or undefined.
 *
 * Returns the FIRST match in registry order, which is why {@link BOT_REGISTRY}
 * must not be sorted: the table arrives ordered by category priority, mirroring
 * `agents.MatchUserAgent` in Go so both sides classify identically.
 */
export function matchUserAgent(userAgent: string | undefined | null): BotAgent | undefined {
  if (!userAgent) return undefined;

  const cached = cache.get(userAgent);
  if (cached !== undefined) return cached ?? undefined;

  const ua = userAgent.toLowerCase();
  let found: BotAgent | null = null;

  for (const agent of BOT_REGISTRY) {
    for (const pattern of agent.uaPatterns) {
      if (ua.includes(pattern)) {
        found = agent;
        break;
      }
    }
    if (found) break;
  }

  if (cache.size >= MAX_CACHE) cache.clear();
  cache.set(userAgent, found);

  return found ?? undefined;
}

/** Classify a User-Agent into the verdict rules evaluate against. */
export function classifyUserAgent(userAgent: string | undefined | null): BotVerdict {
  const agent = matchUserAgent(userAgent);
  if (!agent) return UNKNOWN;

  return {
    known: true,
    id: agent.id,
    name: agent.name,
    category: agent.category,
    organization: agent.organization,
    score: agent.baseScore,
    respectsRobots: agent.respectsRobots,
    isAI: AI_CATEGORIES.has(agent.category),
  };
}

/** Test seam: drop the memoised matches. */
export function clearBotCache(): void {
  cache.clear();
}
