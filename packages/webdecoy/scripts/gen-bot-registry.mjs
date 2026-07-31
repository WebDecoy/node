#!/usr/bin/env node
/**
 * Generate src/bots/registry.generated.ts from the Go agent registry.
 *
 * The Go agent registry in the main application repo is the single source of
 * truth. This
 * script turns its JSON export into a TypeScript module so the SDK can classify a
 * User-Agent locally, with no network call, in the request path.
 *
 * Usage, from the application repo checkout:
 *
 *   cd pkg && go run ./cmd/export-agent-registry \
 *     | node ../../webdecoy-node/packages/webdecoy/scripts/gen-bot-registry.mjs
 *
 * or with an explicit file:
 *
 *   node scripts/gen-bot-registry.mjs agents.json
 *
 * The exporter emits agents already in `agents.MatchUserAgent` order, and this
 * script preserves that order. Do not sort the output: the matcher takes the
 * first hit, and several agents share User-Agent substrings, so reordering
 * silently reclassifies real traffic.
 */

import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'bots', 'registry.generated.ts');

function readInput() {
  const arg = process.argv[2];
  if (arg) return readFileSync(arg, 'utf8');
  return readFileSync(0, 'utf8');
}

const raw = readInput().trim();
if (!raw) {
  console.error('gen-bot-registry: no input. Pipe the exporter output or pass a JSON path.');
  process.exit(1);
}

const { categories, agents } = JSON.parse(raw);

if (!Array.isArray(agents) || agents.length === 0) {
  console.error('gen-bot-registry: input has no agents.');
  process.exit(1);
}
if (!Array.isArray(categories) || categories.length === 0) {
  console.error('gen-bot-registry: input has no categories.');
  process.exit(1);
}

// A pattern that is not already lowercase would never match, because the matcher
// lowercases the User-Agent and compares against the pattern verbatim — same as
// Go's strings.Contains(uaLower, pattern). Catch it here rather than shipping a
// rule that silently never fires.
for (const a of agents) {
  for (const p of a.uaPatterns ?? []) {
    if (p !== p.toLowerCase()) {
      console.error(`gen-bot-registry: agent "${a.id}" has a non-lowercase UA pattern ${JSON.stringify(p)}, which can never match.`);
      process.exit(1);
    }
  }
}

const q = (s) => JSON.stringify(s);

const lines = agents.map((a) => {
  const patterns = (a.uaPatterns ?? []).map(q).join(', ');
  return (
    `  { id: ${q(a.id)}, name: ${q(a.name)}, category: ${q(a.category)}, ` +
    `organization: ${q(a.organization)}, baseScore: ${a.baseScore}, ` +
    `respectsRobots: ${a.respectsRobots === true}, uaPatterns: [${patterns}] },`
  );
});

const out = `/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Source of truth: the Go agent registry in the main application repo.
 * Regenerate with \`packages/webdecoy/scripts/gen-bot-registry.mjs\`; see that
 * script for the command.
 *
 * ORDER IS SIGNIFICANT. Entries are in \`agents.MatchUserAgent\` order — AI data
 * scrapers first, then AI search crawlers, AI agents, search engines, then the
 * remaining categories. \`matchUserAgent()\` returns the first hit, and several
 * agents share User-Agent substrings, so sorting this array changes how real
 * traffic is classified.
 *
 * ${agents.length} agents across ${categories.length} categories.
 */

/**
 * Classification categories, mirroring \`agents.Category\` in Go.
 *
 * Declared here rather than hand-written next door so a category added in Go
 * cannot go missing in TypeScript.
 */
export type BotCategory =
${categories.map((c) => `  | ${q(c)}`).join('\n')};

/** One entry in the registry. */
export interface BotAgent {
  /** Stable lowercase slug, e.g. \`gptbot\`. */
  id: string;
  /** Display name, e.g. \`GPTBot\`. */
  name: string;
  category: BotCategory;
  /** Operator, e.g. \`OpenAI\`. */
  organization: string;
  /** The registry's default threat score for this agent (0-100). */
  baseScore: number;
  /** Whether the operator documents honouring robots.txt. */
  respectsRobots: boolean;
  /** Lowercase User-Agent substrings that identify it. */
  uaPatterns: readonly string[];
}

/** Every declared category, including any with no agents yet. */
export const BOT_CATEGORIES: readonly BotCategory[] = [
${categories.map((c) => `  ${q(c)},`).join('\n')}
];

/** The agent table, in match order. */
export const BOT_REGISTRY: readonly BotAgent[] = [
${lines.join('\n')}
];
`;

writeFileSync(OUT, out);
console.error(`gen-bot-registry: wrote ${agents.length} agents, ${categories.length} categories -> ${OUT}`);
