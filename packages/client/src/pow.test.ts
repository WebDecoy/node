import { getServerUrl, setServerUrl } from './config';
import { InvisibleSession } from './invisible';
import { PoWManager } from './pow';

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
