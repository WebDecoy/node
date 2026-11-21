import { createServer, request, type IncomingHttpHeaders } from 'node:http';
import { rateLimit, tripwire } from './rules';
import { createNodeHttpGuard, type NodeHttpGuard } from './node-http-guard';

async function hit(
  guard: NodeHttpGuard,
  path: string,
  headers: IncomingHttpHeaders = {},
  body?: string
) {
  const server = createServer(async (req, res) => {
    try {
      const outcome = await guard.check(req);
      if (outcome?.response) {
        const { status, headers, body } = outcome.response;
        res.writeHead(status, headers).end(JSON.stringify(body));
        return;
      }

      let input = '';
      req.setEncoding('utf8');
      for await (const chunk of req) input += chunk;
      res.end(JSON.stringify({ conclusion: outcome?.decision.conclusion, input }));
    } catch (error) {
      res.writeHead(500).end(JSON.stringify({ error: String(error) }));
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing TCP address');
    return await new Promise<{ status: number; headers: IncomingHttpHeaders; body: string }>(
      (resolve, reject) => {
        const req = request(
          { host: '127.0.0.1', port: address.port, path, headers, method: body ? 'POST' : 'GET' },
          (res) => {
            let responseBody = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
              responseBody += chunk;
            });
            res.on('error', reject);
            res.on('end', () =>
              resolve({ status: res.statusCode ?? 0, headers: res.headers, body: responseBody })
            );
          }
        );
        req.on('error', reject);
        req.end(body);
      }
    );
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  }
}

describe('createNodeHttpGuard', () => {
  it('reports a tripwire verdict without blocking by default', async () => {
    const result = await hit(createNodeHttpGuard({ rules: [tripwire()] }), '/.env');
    expect(result.status).toBe(200);
    expect(JSON.parse(result.body)).toMatchObject({ conclusion: 'DENY' });
  });

  it('produces a JSON denial in enforce mode and skips configured paths', async () => {
    const guard = createNodeHttpGuard({
      rules: [tripwire()],
      mode: 'enforce',
      skipPaths: ['/health'],
    });
    const protect = jest.spyOn(guard.sdk, 'protect');
    const blocked = await hit(guard, '/.env');
    expect(blocked.status).toBe(403);
    expect(blocked.headers['content-type']).toBe('application/json');
    expect(JSON.parse(blocked.body)).toMatchObject({
      rule: 'tripwire',
      detection_id: expect.any(String),
    });
    expect((await hit(guard, '/health?probe=1')).status).toBe(200);
    expect(protect).toHaveBeenCalledTimes(1);
  });

  it('responds with Retry-After and ignores untrusted forwarded addresses', async () => {
    const guard = createNodeHttpGuard({
      rules: [rateLimit({ max: 1, window: 60 })],
      mode: 'enforce',
    });
    expect((await hit(guard, '/', { 'x-forwarded-for': '192.0.2.1' })).status).toBe(200);
    const limited = await hit(guard, '/', { 'x-forwarded-for': '192.0.2.2' });
    expect(limited.status).toBe(429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('preserves the raw target and body stream and resolves an explicitly trusted proxy', async () => {
    const guard = createNodeHttpGuard({ trustProxy: 1 });
    const protect = jest.spyOn(guard.sdk, 'protect');
    const result = await hit(
      guard,
      'http://example.test/raw/%2Fpath?q=one?two',
      {
        'x-forwarded-for': '192.0.2.1, 198.51.100.3',
      },
      'incoming body'
    );
    expect(result.status).toBe(200);
    expect(JSON.parse(result.body).input).toBe('incoming body');
    expect(protect).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'POST',
        path: '/raw/%2Fpath',
        query: 'q=one?two',
        ip: '198.51.100.3',
      }),
      expect.any(Object)
    );
  });
});
