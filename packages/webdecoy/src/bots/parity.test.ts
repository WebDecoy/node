/**
 * Cross-language parity: this matcher must classify exactly as Go's
 * `agents.MatchUserAgent` does.
 *
 * The two implementations are the reason this test exists. Go scores detections
 * after the fact; TypeScript decides policy in the request path. If they
 * disagree, a customer blocks GPTBot in their rules and then sees the blocked
 * request filed under a different agent — or worse, agrees in testing and
 * diverges months later when someone reorders the registry.
 *
 * The vectors are RECORDED FROM GO, not hand-written:
 *
 *   cd pkg && go run ./cmd/export-agent-registry -golden \
 *     > ../../webdecoy-node/packages/webdecoy/src/bots/parity-vectors.generated.json
 *
 * Regenerate them in the same commit as any registry change. A vector file that
 * disagrees with the generated table means the two were exported from different
 * revisions.
 */

import { matchUserAgent, classifyUserAgent } from './index';
import vectors from './parity-vectors.generated.json';

interface Vector {
  userAgent: string;
  id?: string;
  category?: string;
  matched: boolean;
}

const cases = vectors as Vector[];

describe('parity with the Go matcher', () => {
  it('has a non-trivial corpus', () => {
    // Guards against the vector file being emptied or replaced by `[]`, which
    // would make every assertion below vacuously pass.
    expect(cases.length).toBeGreaterThan(300);
    expect(cases.some((v) => v.matched)).toBe(true);
    expect(cases.some((v) => !v.matched)).toBe(true);
  });

  it('agrees with Go on every recorded User-Agent', () => {
    const disagreements: string[] = [];

    for (const v of cases) {
      const got = matchUserAgent(v.userAgent);

      if (!v.matched) {
        if (got) disagreements.push(`${JSON.stringify(v.userAgent)}: Go matched nothing, TS matched ${got.id}`);
        continue;
      }

      if (!got) {
        disagreements.push(`${JSON.stringify(v.userAgent)}: Go matched ${v.id}, TS matched nothing`);
        continue;
      }
      if (got.id !== v.id) {
        disagreements.push(`${JSON.stringify(v.userAgent)}: Go matched ${v.id}, TS matched ${got.id}`);
        continue;
      }
      if (got.category !== v.category) {
        disagreements.push(
          `${JSON.stringify(v.userAgent)}: category Go=${v.category} TS=${got.category}`,
        );
      }
    }

    expect(disagreements).toEqual([]);
  });

  it('never classifies a real browser as a bot', () => {
    // Called out separately from the sweep above because this is the failure
    // that blocks paying customers rather than merely mislabelling a crawler.
    const browsers = cases.filter((v) => v.userAgent.includes('Mozilla/5.0 (') && !v.matched);
    expect(browsers.length).toBeGreaterThan(0);
    for (const b of browsers) {
      expect(classifyUserAgent(b.userAgent).known).toBe(false);
    }
  });
});
