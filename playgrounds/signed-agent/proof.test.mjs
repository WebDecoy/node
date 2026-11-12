import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runProof } from './proof.mjs';

test('real Ed25519 signatures distinguish trusted, modified, expired, unknown and unsigned requests', async () => {
  const proof = await runProof();
  const cases = Object.fromEntries(proof.results.map(row => [row.scenario, row]));
  assert.equal(cases.valid.status, 'verified');
  assert.equal(cases.valid.agent, 'Demo Agent (local fixture)');
  assert.equal(cases.tampered.status, 'impersonation');
  assert.equal(cases.tampered.reason, 'bad-signature');
  assert.equal(cases.expired.status, 'impersonation');
  assert.equal(cases.expired.reason, 'expired');
  assert.equal(cases['unknown signer'].status, 'claimed');
  assert.equal(cases['unknown signer'].reason, 'unknown-key');
  assert.equal(cases.unsigned.status, 'none');
  assert.equal(proof.directoryReads, 1, 'the same verifier should reuse the fixture directory keys');
});
