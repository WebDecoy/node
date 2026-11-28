import { expect, test } from 'bun:test';
import { startDemo } from './server';

test.each([
  ['monitor', 404],
  ['enforce', 403],
] as const)('%s keeps the ordinary route available', async (mode, decoyStatus) => {
  const decisions: Array<[string, string]> = [];
  const server = startDemo({ mode, port: 0, onDecision: (path, verdict) => decisions.push([path, verdict]) });
  try {
    const ordinary = await fetch(server.url);
    expect(ordinary.status).toBe(200);
    expect(await ordinary.text()).toBe('Hello from Elysia');

    const decoy = await fetch(new URL('/demo-decoy', server.url));
    expect(decoy.status).toBe(decoyStatus);
    await decoy.text();
    expect(decisions).toEqual([['/', 'ALLOW'], ['/demo-decoy', 'DENY']]);
  } finally {
    await server.stop(true);
  }
});
