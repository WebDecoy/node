import { pathToFileURL } from 'node:url';
import webdecoy from '@webdecoy/fastify';
import { tripwire } from '@webdecoy/node';
import Fastify from 'fastify';

export async function createServer({ onDecision = console.log } = {}) {
  const { handler: render } = await import('./dist/server/entry.mjs');
  const app = Fastify();
  await app.register(webdecoy, {
    mode: 'monitor',
    honeytoken: false,
    rules: [tripwire({ paths: ['/lab/check/'] })],
  });

  app.addHook('preHandler', async (request) => {
    const decision = request.webdecoyDecision;
    if (decision) {
      onDecision({
        method: request.method,
        route: request.routeOptions.url,
        conclusion: decision.conclusion,
        tripwire: decision.deniedBy('tripwire'),
      });
    }
  });

  app.get('/lab/check/', async (_, reply) => {
    return reply.code(404).send({ error: 'Not found' });
  });

  async function renderAstro(request, reply) {
    reply.hijack();
    await render(request.raw, reply.raw, () => {
      reply.raw.writeHead(404).end('Not found');
    });
  }

  app.get('/', renderAstro);
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await createServer();
  console.log(await server.listen({ host: '127.0.0.1', port: 4321 }));
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => void server.close());
  }
}
