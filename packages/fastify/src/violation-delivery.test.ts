import Fastify from 'fastify';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tripwire } from '@webdecoy/node';
import { webdecoyPlugin } from './plugin';

// fastify.close() is how an app shuts down. The plugin's SDK is private, so
// the plugin itself has to send what its reporter still holds at that point.
test('fastify.close() delivers the violations the plugin still holds', async () => {
  const received: { path?: string; eventId?: string }[] = [];
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    if (request.url === '/api/v1/sdk/violations/batch') received.push(...JSON.parse(body).events);
    response.writeHead(201).end('{}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const apiUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  try {
    const app = Fastify();
    await app.register(webdecoyPlugin, {
      apiKey: 'sk_test_fastify_delivery', apiUrl, countAIReferrals: false, honeytoken: false,
      mode: 'enforce', rules: [tripwire({ includeDefaults: false, paths: ['/trap'] })],
    });
    app.get('/*', async () => 'ok');

    const res = await app.inject({ method: 'GET', url: '/trap' });
    expect(res.statusCode).toBe(403);
    // Buffered, not yet sent: the reporter batches on an interval.
    expect(received).toEqual([]);

    await app.close();
    expect(received).toEqual([expect.objectContaining({ path: '/trap', eventId: expect.any(String) })]);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
