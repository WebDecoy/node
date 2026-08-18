/**
 * The reserved test trigger.
 *
 * A request whose User-Agent starts with `WebDecoy-Test/` is the documented
 * install-verification probe:
 *
 *     curl -A "WebDecoy-Test/1.0" http://localhost:3000/
 *
 * The SDK always reports it to ingest — before rules, before local-analysis
 * thresholds, before sampling of any kind — so the developer who just
 * installed the middleware gets a guaranteed, labeled detection in the
 * dashboard within seconds, including from localhost. Ingest recognizes the
 * same prefix server-side, marks the row `is_test`, and keeps it out of
 * stats, billing, actor scoring, and enforcement.
 *
 * Prefix-anchored on purpose: a UA that merely mentions the string mid-way
 * is NOT the trigger, so real traffic can't hide behind the test label.
 */

/** Any User-Agent starting with this (case-insensitive) is a test trigger. */
export const TEST_TRIGGER_UA_PREFIX = 'WebDecoy-Test/';

/** The exact value the quickstart docs tell developers to send. */
export const TEST_TRIGGER_USER_AGENT = 'WebDecoy-Test/1.0';

/** Whether this User-Agent is the reserved test trigger. */
export function isTestTriggerUserAgent(userAgent: string | undefined): boolean {
  if (!userAgent) return false;
  return userAgent.trimStart().toLowerCase().startsWith(TEST_TRIGGER_UA_PREFIX.toLowerCase());
}
