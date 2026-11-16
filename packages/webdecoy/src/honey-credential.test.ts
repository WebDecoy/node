import { WebDecoy } from './sdk';

describe('honey credential correlation', () => {
  const realFetch = global.fetch;

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('never sends the bearer or a mismatched presented credential', async () => {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    global.fetch = jest.fn(async (url: unknown, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      calls.push({ url: String(url), body });
      if (String(url).endsWith('/honey-credentials')) {
        return new Response(
          JSON.stringify({
            token_id: body.token_id,
            expires_at: '2026-12-15T21:00:00Z',
            test: true,
          }),
          { status: 201 }
        );
      }
      return new Response(
        JSON.stringify({
          detection_id: crypto.randomUUID(),
          token_id: body.token_id,
          test: true,
        }),
        { status: 201 }
      );
    }) as jest.Mock;

    const sdk = new WebDecoy({ apiKey: 'sk_test_honey', apiUrl: 'https://ingest.example' });
    const created = await sdk.createHoneyCredential({
      propertyId: '8c6459a9-6219-4f61-ad88-b0e4f1774249',
      test: true,
    });
    await sdk.reportHoneyCredentialRetrieval(created.handle, '/decoy/config');

    const realCredential = 'prod-secret-that-must-stay-local';
    await expect(
      sdk.observeHoneyCredentialPresentation(realCredential, created.handle, '/login')
    ).resolves.toEqual({ matched: false });
    expect(calls).toHaveLength(2);

    const matched = await sdk.observeHoneyCredentialPresentation(
      created.bearer,
      created.handle,
      '/login'
    );
    expect(matched.matched).toBe(true);
    expect(calls).toHaveLength(3);
    expect(calls[2].url).toBe('https://ingest.example/api/v1/sdk/honey-credentials/presentation');

    const wire = JSON.stringify(calls);
    expect(wire).not.toContain(created.bearer);
    expect(wire).not.toContain(realCredential);
    expect(wire).not.toContain('authorization');
    expect(wire).not.toContain('request_body');
  });

  it('requires hosted reporting', async () => {
    const sdk = new WebDecoy();
    await expect(sdk.createHoneyCredential()).rejects.toThrow(/apiKey/);
  });
});
