import { WebDecoy } from './sdk';

describe('SSRF canary correlation', () => {
  const realFetch = global.fetch;

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('reports only the marker ID and route template on the initiation edge', async () => {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    global.fetch = jest.fn(async (url: unknown, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      calls.push({ url: String(url), body });
      if (String(url).endsWith('/ssrf/markers')) {
        return new Response(
          JSON.stringify({
            marker_id: 'd65fd38c-4f45-4f32-91cf-1cdcd9c03fe6',
            callback_url: 'https://ingest.example/api/v1/ssrf/callback/opaque-token',
            route_template: '/api/fetch/:id',
            expires_at: '2026-11-15T21:00:00Z',
            test: true,
            token: 'must-not-be-returned-by-the-sdk',
          }),
          { status: 201 }
        );
      }
      return new Response(
        JSON.stringify({
          detection_id: 'c18348c8-9f6b-43e9-b993-86ca15db257f',
          marker_id: body.marker_id,
          test: true,
        }),
        { status: 201 }
      );
    }) as jest.Mock;

    const sdk = new WebDecoy({ apiKey: 'sk_test_ssrf', apiUrl: 'https://ingest.example' });
    const canary = await sdk.createSSRFCanary({ routeTemplate: '/api/fetch/:id', test: true });
    const receipt = await sdk.reportSSRFInitiation(canary);

    expect(canary).toEqual({
      markerId: 'd65fd38c-4f45-4f32-91cf-1cdcd9c03fe6',
      callbackUrl: 'https://ingest.example/api/v1/ssrf/callback/opaque-token',
      routeTemplate: '/api/fetch/:id',
      expiresAt: '2026-11-15T21:00:00Z',
      test: true,
    });
    expect(receipt.detectionId).toBe('c18348c8-9f6b-43e9-b993-86ca15db257f');
    expect(calls[1]).toEqual({
      url: 'https://ingest.example/api/v1/sdk/ssrf/initiate',
      body: {
        marker_id: 'd65fd38c-4f45-4f32-91cf-1cdcd9c03fe6',
        route_template: '/api/fetch/:id',
      },
    });
    expect(JSON.stringify(calls[1].body)).not.toContain('opaque-token');
  });

  it('requires a hosted API key', async () => {
    const sdk = new WebDecoy();
    await expect(sdk.createSSRFCanary({ routeTemplate: '/fetch' })).rejects.toThrow(/apiKey/);
  });
});
