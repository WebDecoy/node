import { createFetchGuard, tripwire } from '@webdecoy/node';
import { Elysia } from 'elysia';

interface DemoOptions {
  port?: number;
  mode?: 'monitor' | 'enforce';
  onDecision?: (path: string, conclusion: string) => void;
}

export function startDemo({ port = 3000, mode = 'monitor', onDecision }: DemoOptions = {}) {
  const app = new Elysia().get('/', () => 'Hello from Elysia');
  const guard = createFetchGuard({
    mode,
    trustProxy: 0,
    rules: [tripwire({ paths: ['/demo-decoy'], includeDefaults: false })],
  });

  return Bun.serve({
    hostname: '127.0.0.1',
    port,
    async fetch(request, server) {
      const { decision, response } = await guard.check(request, server.requestIP(request)?.address);
      onDecision?.(new URL(request.url).pathname, decision.conclusion);
      return response ?? app.handle(request);
    },
  });
}

if (import.meta.main) {
  const server = startDemo({ onDecision: (path, verdict) => console.log(verdict, path) });
  console.log(`Elysia demo listening at ${server.url}`);
}
