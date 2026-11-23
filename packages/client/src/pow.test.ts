import { EnvironmentalCollector } from './collectors/environment';
import { getServerUrl, setServerUrl } from './config';
import { InvisibleSession } from './invisible';
import { PoWManager } from './pow';

jest.mock('./sha256', () => ({ sha256: async () => 'fixture-hash' }));

const globalFetch = globalThis.fetch;
const originalOrigin = getServerUrl();
const challengeData = {
  prefix: 'fixture:123:2',
  difficulty: 2,
  expiresAt: 1_000_000,
  nonce: 'fixture-nonce',
};

function serveChallenge(body: unknown): jest.Mock {
  const fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => body });
  globalThis.fetch = fetch;
  return fetch;
}

afterEach(() => {
  setServerUrl(originalOrigin);
  globalThis.fetch = globalFetch;
});

it.each(['id', 'challengeId'])('normalizes a challenge with the %s field', async field => {
  setServerUrl('https://captcha.example.test');
  const fetch = serveChallenge({ [field]: 'fixture', ...challengeData });

  const manager = new PoWManager();
  expect(await manager.fetchChallenge('test-site')).toEqual({ challengeId: 'fixture', ...challengeData });
  expect(fetch).toHaveBeenCalledWith('https://captcha.example.test/__webdecoy/challenge?siteKey=test-site');
});

it('fetches the invisible session challenge from its configured origin', () => {
  setServerUrl('https://global.example.test');
  const fetch = serveChallenge({ id: 'fixture', ...challengeData });
  const session = new InvisibleSession({
    siteKey: 'test-site',
    serverUrl: 'https://session.example.test',
    autoScore: false,
  });

  try {
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith('https://session.example.test/__webdecoy/challenge?siteKey=test-site');
  } finally {
    session.destroy();
  }
});


it('binds consecutive invisible scores to their own challenges', async () => {
  const instance = 'https://session.example.test';
  const posted: Array<{ signalsJson: string; powSolution: { challengeId: string } }> = [];
  let challengeCount = 0;
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    if (String(url).includes('/challenge?')) {
      const id = String(++challengeCount);
      return { ok: true, json: async () => ({
        ...challengeData, id, nonce: 'nonce-' + id, expiresAt: Date.now() + 60_000,
      }) } as Response;
    }

    expect(init?.credentials).toBe('same-origin');
    posted.push(JSON.parse(init?.body as string));
    return { ok: true, json: async () => ({ success: true, token: 'fixture-token' }) } as Response;
  });

  const collect = jest.spyOn(EnvironmentalCollector.prototype, 'collect').mockReturnValue({});
  const asyncCollect = jest.spyOn(EnvironmentalCollector.prototype, 'collectAsync').mockResolvedValue({});
  const frames = jest.spyOn(EnvironmentalCollector.prototype, 'measureRAFConsistency').mockResolvedValue({});
  const solve = jest.spyOn(PoWManager.prototype, 'solveWithSignalsHash').mockImplementation(async function (this: PoWManager) {
    return {
      challengeId: this.challenge!.challengeId,
      nonce: 2, hash: 'test-hash', iterations: 10, duration: 25, difficulty: 2,
      signalsHash: 'fixture-hash', local: false,
    };
  });
  const session = new InvisibleSession({ serverUrl: instance, autoScore: false, minCollectionTime: 0 });
  try {
    await Promise.all([session.execute('first'), session.execute('second')]);

    expect(challengeCount).toBe(2);
    expect(posted.map(({ signalsJson, powSolution }) => ({
      action: JSON.parse(signalsJson).meta.action,
      challengeNonce: JSON.parse(signalsJson).meta.challengeNonce,
      challengeId: powSolution.challengeId,
    }))).toEqual([
      { action: 'first', challengeNonce: 'nonce-1', challengeId: '1' },
      { action: 'second', challengeNonce: 'nonce-2', challengeId: '2' },
    ]);
  } finally {
    session.destroy();
    for (const spy of [collect, asyncCollect, frames, solve]) spy.mockRestore();
  }
});
