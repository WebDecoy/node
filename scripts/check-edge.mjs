/**
 * Edge-runtime compatibility gate.
 *
 * Bundles each entry point with esbuild targeting the browser platform, where
 * Node built-ins (`crypto`, `net`, `https`, ...) do not resolve. Any Node-only
 * import anywhere in the module graph fails the build — the same failure a
 * consumer would hit deploying the package in Vercel Edge Middleware.
 *
 * Usage: node scripts/check-edge.mjs <entry.ts> [...more entries]
 * Framework packages keep their host externals (next, express, fastify).
 */

import { build } from 'esbuild';

const entries = process.argv.slice(2);
if (entries.length === 0) {
  console.error('usage: node check-edge.mjs <entry.ts> [...entries]');
  process.exit(2);
}

let failed = false;

for (const entry of entries) {
  try {
    await build({
      entryPoints: [entry],
      bundle: true,
      write: false,
      platform: 'browser',
      format: 'esm',
      logLevel: 'silent',
      external: ['next', 'next/*', 'express', 'fastify', 'fastify-plugin'],
    });
    console.log(`✓ edge-compatible: ${entry}`);
  } catch (error) {
    failed = true;
    console.error(`✗ NOT edge-compatible: ${entry}`);
    for (const e of error.errors ?? []) {
      console.error(`  ${e.text}${e.location ? ` (${e.location.file}:${e.location.line})` : ''}`);
    }
  }
}

process.exit(failed ? 1 : 0);
