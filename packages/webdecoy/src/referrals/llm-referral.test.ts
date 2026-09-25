import vectors from './llm-referral-vectors.generated.json';
import { classifyReferral } from './llm-referral';
import { AIReferralCounter, type AIReferralBatch } from './referral-counter';
import type { RequestMetadata } from '../types';

// Generated from WebDecoy's own classifier: this port must agree case for case.
describe('classifyReferral matches the shared classifier', () => {
  it.each(vectors.map((v) => [v.referer || '(none)', v.page_url, v] as const))('%s -> %s', (_r, _p, v) => {
    expect(classifyReferral(v.referer, v.page_url)).toBe(v.platform);
  });
});

describe('AIReferralCounter', () => {
  const visit = (over: { referer?: string; path?: string; query?: string } = {}): RequestMetadata => ({
    method: 'GET',
    path: over.path ?? '/pricing',
    query: over.query,
    ip: '203.0.113.9',
    timestamp: Date.now(),
    headers: {
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'document',
      ...(over.referer ? { referer: over.referer } : {}),
    },
  });

  it('counts AI page visits by platform and path, and nothing else', async () => {
    const sent: AIReferralBatch[] = [];
    const counter = new AIReferralCounter({ sendAIReferrals: async (b) => (sent.push(b), true) });
    counter.observe(visit({ referer: 'https://chatgpt.com/c/1' }));
    counter.observe(visit({ referer: 'https://chatgpt.com/' }));
    counter.observe(visit({ path: '/blog', query: 'utm_source=perplexity.ai&email=a' }));
    counter.observe(visit({ referer: 'https://www.google.com/' }));
    counter.observe({ ...visit({ referer: 'https://chatgpt.com/' }), method: 'POST' });
    counter.observe({ ...visit({ referer: 'https://chatgpt.com/' }), headers: { referer: 'https://chatgpt.com/' } });
    await counter.destroy();
    expect(sent).toHaveLength(1);
    expect(sent[0].source).toBe('sdk');
    expect(sent[0].referrals).toEqual([
      { platform: 'ChatGPT', path: '/pricing', count: 2 },
      { platform: 'Perplexity', path: '/blog', count: 1 },
    ]);
    expect(JSON.stringify(sent)).not.toMatch(/203\.0\.113|email/);
  });

  it('retries a failed batch under the same id, so it counts once', async () => {
    const ids: string[] = [];
    let accept = false;
    const counter = new AIReferralCounter({
      sendAIReferrals: async (b) => (ids.push(b.report_id), accept),
    });
    counter.observe(visit({ referer: 'https://claude.ai/' }));
    await counter.flush();
    accept = true;
    counter.observe(visit({ referer: 'https://claude.ai/' })); // counted into the next batch
    await counter.flush();
    await counter.destroy();
    expect(ids[0]).toBe(ids[1]);
    expect(ids).toHaveLength(3);
    expect(ids[2]).not.toBe(ids[0]);
  });
});
