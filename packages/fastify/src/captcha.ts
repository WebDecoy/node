/**
 * Fastify captcha endpoints plugin.
 *
 * Registers the WebDecoy captcha routes under a base path. Fastify parses JSON
 * bodies automatically.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { webdecoyCaptchaPlugin } from '@webdecoy/fastify';
 *
 * const app = Fastify();
 * app.register(webdecoyCaptchaPlugin, { secret: process.env.WEBDECOY_SECRET });
 * ```
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import { createCaptchaEndpoints, type CaptchaEndpointsOptions } from '@webdecoy/node';

async function plugin(fastify: FastifyInstance, options: CaptchaEndpointsOptions): Promise<void> {
  const endpoints = createCaptchaEndpoints(options);

  fastify.route({
    method: ['GET', 'POST'],
    url: `${endpoints.basePath}/*`,
    handler: async (request: FastifyRequest, reply: FastifyReply) => {
      const pathname = request.url.split('?')[0];
      const query = (request.query ?? {}) as Record<string, string | undefined>;

      const result = await endpoints.handle({
        method: request.method,
        pathname,
        query,
        headers: request.headers as Record<string, string>,
        body: request.body,
        ip: request.ip,
      });

      if (!result) {
        reply.code(404).send({ error: 'not_found' });
        return;
      }

      reply.code(result.status);
      for (const [k, v] of Object.entries(result.headers)) reply.header(k, v);
      reply.send(result.body);
    },
  });
}

export const webdecoyCaptchaPlugin = fp(plugin, {
  fastify: '4.x || 5.x',
  name: '@webdecoy/captcha',
});
