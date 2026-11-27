#!/usr/bin/env node
// Which public packages have a version that npm does not have yet.
//
// The publish workflow runs this on every push to main. A package whose
// package.json version is already on the registry is skipped, so a re-run
// after a partial failure publishes only what is missing, and a push that
// bumps nothing publishes nothing.
//
// Prints JSON: { version, packages: [{ name, dir }] }, in publish order
// (the core SDK first, then the packages that depend on it).
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ORDER = ['@webdecoy/node', '@webdecoy/client'];

export function publishOrder(names) {
  return [...names].sort((a, b) => {
    const ia = ORDER.indexOf(a);
    const ib = ORDER.indexOf(b);
    return (ia === -1 ? ORDER.length : ia) - (ib === -1 ? ORDER.length : ib) || a.localeCompare(b);
  });
}

export function readPackages(root) {
  return readdirSync(join(root, 'packages'), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => {
      const dir = join('packages', d.name);
      const pkg = JSON.parse(readFileSync(join(root, dir, 'package.json'), 'utf8'));
      return { name: pkg.name, version: pkg.version, private: pkg.private === true, dir };
    })
    .filter((p) => !p.private);
}

async function published(name, version, fetchImpl) {
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace('/', '%2f')}/${version}`, {
    headers: { accept: 'application/json' },
  });
  if (res.status === 404) return false;
  if (!res.ok) throw new Error(`registry answered ${res.status} for ${name}@${version}`);
  return true;
}

export async function plan(root, fetchImpl = fetch) {
  const pkgs = readPackages(root);
  const versions = new Set(pkgs.map((p) => p.version));
  if (versions.size !== 1) {
    throw new Error(`packages disagree on the version: ${pkgs.map((p) => `${p.name}@${p.version}`).join(', ')}`);
  }
  const [version] = versions;
  const missing = [];
  for (const p of pkgs) {
    if (!(await published(p.name, p.version, fetchImpl))) missing.push(p);
  }
  const byName = new Map(missing.map((p) => [p.name, p]));
  return {
    version,
    packages: publishOrder(byName.keys()).map((n) => ({ name: n, dir: byName.get(n).dir })),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(await plan(process.cwd())));
}
