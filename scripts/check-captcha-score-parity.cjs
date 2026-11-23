/**
 * Compare scoring policy with synthetic detector evidence and an accepted proof.
 * Pass the engine.js file from the FCaptcha commit recorded in the fixture.
 * Build @webdecoy/node first so this uses its packaged scoring exports.
 */
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const fixtures = require('../packages/webdecoy/src/detection/fixtures/scoring-policy.json');
const enginePath = process.argv[2];
assert.ok(enginePath, 'Pass the pinned FCaptcha server-node/engine.js path');
const hash = createHash('sha256').update(readFileSync(resolve(enginePath))).digest('hex');
assert.equal(hash, fixtures.reference.engineSha256, 'Use FCaptcha ' + fixtures.reference.commit);

const reference = require(resolve(enginePath));
const embedded = require('../packages/webdecoy/dist/index.js');

function assertOutcome(score, recommendation, expected, label) {
  assert.ok(Math.abs(score - expected.score) < 1e-10, label + ' score');
  assert.equal(recommendation, expected.recommendation, label + ' recommendation');
  assert.equal(score < 0.5, expected.success, label + ' success with accepted proof');
}

for (const fixture of fixtures.cases) {
  const { name, detections } = fixture;
  const embeddedScores = embedded.calculateCategoryScores(detections, embedded.DEFAULT_WEIGHTS);
  const embeddedScore = embedded.calculateFinalScore(embeddedScores, embedded.DEFAULT_WEIGHTS);
  assertOutcome(embeddedScore, embedded.recommend(embeddedScore), fixture.embedded, name + ' (Node)');

  const referenceScores = reference.calculateCategoryScores(detections);
  const referenceScore = reference.applyCorroborationFloor(
    reference.applyDispositiveFloor(reference.calculateFinalScore(referenceScores), detections),
    detections,
  );
  const recommendation = referenceScore < 0.3 ? 'allow' : referenceScore < 0.6 ? 'challenge' : 'block';
  assertOutcome(referenceScore, recommendation, fixture.reference, name + ' (FCaptcha)');
  console.log(name + ' — Node ' + fixture.embedded.recommendation + ', FCaptcha ' + recommendation);
}

for (const { name, environmental, referenceFloor } of fixtures.decisiveFloorCases) {
  if (referenceFloor === undefined) continue;
  const signals = { environmental };
  const detections = [...reference.detectHeadless(signals, ''), ...reference.detectCDP(signals)];
  const floor = reference.applyDispositiveFloor(0, detections);
  assert.equal(floor, referenceFloor, name + ' (FCaptcha decisive floor)');
  console.log(name + ' — FCaptcha decisive floor ' + floor);
}

for (const { name, signals, referenceFloor } of fixtures.corroborationFloorCases) {
  if (referenceFloor === undefined) continue;
  const detections = [
    ...reference.detectVisionAI(signals),
    ...reference.detectBehavioral(signals),
    ...reference.detectCDP(signals),
  ];
  const floor = reference.applyCorroborationFloor(0, detections);
  assert.equal(floor, referenceFloor, name + ' (FCaptcha corroboration floor)');
  console.log(name + ' — FCaptcha corroboration floor ' + floor);
}
