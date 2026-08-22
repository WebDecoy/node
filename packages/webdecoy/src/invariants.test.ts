import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * Invariants a reviewer cannot see.
 *
 * Every finding in the 0.12.0 / 0.13.0 batch was the same shape: two places
 * answering one question, and the surface picking the more flattering answer.
 * The spoofable client IP survived in two adapters after the WordPress plugin
 * had already fixed the same class of bug, because each call site read perfectly
 * reasonably on its own and nothing connected them.
 *
 * These tests connect them. They read source rather than behaviour on purpose:
 * the defect is never "this function is wrong", it is "there are two of these
 * and they disagree", which no unit test of either one can catch.
 */

const PACKAGES = join(__dirname, '..', '..');

/** Every shipped .ts file across the workspace, tests and builds excluded. */
function sourceFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (entry === 'node_modules' || entry === 'dist' || entry === '.turbo') continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.endsWith('.ts')) continue;
      if (entry.endsWith('.test.ts') || entry.endsWith('.spec.ts')) continue;
      if (entry.endsWith('.generated.ts')) continue;
      out.push(full);
    }
  };
  walk(PACKAGES);
  return out;
}

/** Lines of `file` that contain `needle`, ignoring comments. */
function hits(file: string, needle: RegExp): string[] {
  const found: string[] = [];
  readFileSync(file, 'utf8')
    .split('\n')
    .forEach((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;
      if (needle.test(line)) found.push(`${relative(PACKAGES, file)}:${i + 1}`);
    });
  return found;
}

describe('one answer to "who is the client"', () => {
  it('resolves the client IP only in client-ip.ts', () => {
    // Reading a forwarding header anywhere else is how the leftmost-XFF bug
    // lived in Express and Next.js after the same bug had been fixed elsewhere:
    // three adapters, three copies, and no one place to correct.
    const offenders = sourceFiles()
      .filter((f) => !f.endsWith(join('webdecoy', 'src', 'client-ip.ts')))
      // Matches *reading* the header to derive an address —
      // `headers['x-forwarded-for']` or `.get('x-forwarded-for')` — not merely
      // naming it. The detection engine legitimately lists these among the
      // headers it inspects for suspicious shapes, and that is not IP
      // resolution.
      .flatMap((f) =>
        hits(
          f,
          /(?:\.get\(|\[)\s*['"](?:x-forwarded-for|x-real-ip|cf-connecting-ip)['"]/i,
        ),
      );

    if (offenders.length > 0) {
      throw new Error(
        'These read a forwarding header directly instead of calling resolveClientIp().\n' +
          'The leftmost value of X-Forwarded-For is written by the client, so trusting\n' +
          'it hands an attacker the rate-limit key and the address on every detection.\n' +
          'Use resolveClientIp({ headers, peer, trustProxy }).\n\n  ' +
          offenders.join('\n  '),
      );
    }
  });
});

describe('one answer to "what did we decide"', () => {
  it('builds decisions only through the Decision class', () => {
    // protect() returning a plain object literal is how `allowed` and
    // `conclusion` drift apart, and how a spread silently strips the narrowing
    // helpers off the result.
    const sdk = join(PACKAGES, 'webdecoy', 'src', 'sdk.ts');
    const source = readFileSync(sdk, 'utf8');

    if (/return\s*\{\s*\n?\s*allowed:/.test(source)) {
      throw new Error(
        'sdk.ts returns a bare object with an `allowed` key. Every decision must be\n' +
          'a `new Decision({...})`, or the conclusion and the boolean can disagree\n' +
          'and the narrowing helpers are lost on the way out.',
      );
    }
  });

  it('never spreads a decision, which would drop its methods', () => {
    const sdk = readFileSync(join(PACKAGES, 'webdecoy', 'src', 'sdk.ts'), 'utf8');

    if (/\{\s*\.\.\.(result|decision)\s*,/.test(sdk)) {
      throw new Error(
        'Spreading a Decision produces a plain object: `isDenied()` and `deniedBy()`\n' +
          'vanish and the adapter silently loses them. Use decision.withEdge(...) or\n' +
          'another method that returns a Decision.',
      );
    }
  });
});

describe('one answer to "is this rule running"', () => {
  it('every rule that can be starved reports NOT_RUN rather than ALLOW', () => {
    // A rule that cannot evaluate must say so. Reporting ALLOW makes "checked
    // and fine" indistinguishable from "never checked", which is how a filter
    // rule with no enrichment looked like a passing IP reputation check.
    const starvable = ['filter-rule.ts', 'web-bot-auth-rule.ts', 'rate-limit-rule.ts'];

    for (const name of starvable) {
      const source = readFileSync(join(PACKAGES, 'webdecoy', 'src', 'rules', name), 'utf8');
      if (!source.includes("state: 'NOT_RUN'")) {
        throw new Error(
          `${name} has no NOT_RUN path. A rule that silently allows when its input ` +
            `is missing is indistinguishable from one that ran and passed.`,
        );
      }
    }
  });
});

describe('the edge build stays edge-compatible', () => {
  it('no node: import reaches a package that ships to Workers', () => {
    // check:edge catches this at build time, but only for the entry points it
    // is pointed at. This catches it in review, with the file named.
    const edgePackages = ['webdecoy', 'nextjs', 'hono'];
    const offenders = sourceFiles()
      .filter((f) => edgePackages.some((p) => f.includes(join(PACKAGES, p, 'src'))))
      .flatMap((f) => hits(f, /from ['"]node:/));

    if (offenders.length > 0) {
      throw new Error(
        'A `node:` import anywhere in these graphs breaks the bundle for Cloudflare\n' +
          'Workers and Vercel Edge, where most of this SDK is meant to run.\n\n  ' +
          offenders.join('\n  '),
      );
    }
  });
});
