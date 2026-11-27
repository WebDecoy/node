import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { plan, publishOrder } from './publish-plan.mjs';

function repo(pkgs) {
  const root = mkdtempSync(join(tmpdir(), 'publish-plan-'));
  for (const [dir, pkg] of Object.entries(pkgs)) {
    mkdirSync(join(root, 'packages', dir), { recursive: true });
    writeFileSync(join(root, 'packages', dir, 'package.json'), JSON.stringify(pkg));
  }
  return root;
}

const registry = (have) => async (url) => {
  const [, name, version] = url.match(/npmjs\.org\/(.+)\/([^/]+)$/);
  return { status: have.has(`${decodeURIComponent(name)}@${version}`) ? 200 : 404, ok: true };
};

test('publishes only the versions npm does not have, core SDK first', async () => {
  const root = repo({
    express: { name: '@webdecoy/express', version: '1.2.0' },
    webdecoy: { name: '@webdecoy/node', version: '1.2.0' },
    client: { name: '@webdecoy/client', version: '1.2.0' },
  });
  const result = await plan(root, registry(new Set(['@webdecoy/client@1.2.0'])));
  assert.equal(result.version, '1.2.0');
  assert.deepEqual(result.packages.map((p) => p.name), ['@webdecoy/node', '@webdecoy/express']);
});

test('a push that bumps nothing publishes nothing', async () => {
  const root = repo({ webdecoy: { name: '@webdecoy/node', version: '1.2.0' } });
  const result = await plan(root, registry(new Set(['@webdecoy/node@1.2.0'])));
  assert.deepEqual(result.packages, []);
});

test('private packages are never published', async () => {
  const root = repo({
    webdecoy: { name: '@webdecoy/node', version: '1.2.0' },
    internal: { name: '@webdecoy/internal', version: '1.2.0', private: true },
  });
  const result = await plan(root, registry(new Set()));
  assert.deepEqual(result.packages.map((p) => p.name), ['@webdecoy/node']);
});

test('refuses when packages disagree on the version', async () => {
  const root = repo({
    webdecoy: { name: '@webdecoy/node', version: '1.2.0' },
    express: { name: '@webdecoy/express', version: '1.1.0' },
  });
  await assert.rejects(plan(root, registry(new Set())), /disagree/);
});

test('a registry error stops the plan rather than publishing blind', async () => {
  const root = repo({ webdecoy: { name: '@webdecoy/node', version: '1.2.0' } });
  await assert.rejects(plan(root, async () => ({ status: 503, ok: false })), /503/);
});

test('order puts the core SDK and client ahead of adapters', () => {
  assert.deepEqual(publishOrder(['@webdecoy/hono', '@webdecoy/client', '@webdecoy/node']), [
    '@webdecoy/node',
    '@webdecoy/client',
    '@webdecoy/hono',
  ]);
});
