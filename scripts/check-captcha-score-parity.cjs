/**
 * Compare scoring policy and detector reason IDs using fixtures and an accepted proof.
 * Pass the engine.js file from the FCaptcha commit recorded in the fixture.
 * Build @webdecoy/node first so this uses its packaged scoring exports.
 */
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const fixtures = require('../packages/webdecoy/src/detection/fixtures/scoring-policy.json');
const inputModality = require('../packages/webdecoy/src/detection/fixtures/input-modality.json');
const enginePath = process.argv[2];
assert.ok(enginePath, 'Pass the pinned FCaptcha server-node/engine.js path');
const hash = createHash('sha256').update(readFileSync(resolve(enginePath))).digest('hex');
assert.equal(hash, fixtures.reference.engineSha256, 'Use FCaptcha ' + fixtures.reference.commit);

const reference = require(resolve(enginePath));
const embedded = require('../packages/webdecoy/dist/index.js');

const reasonIds = {
  vision_ai: {
    'No mouse movement detected before click (AI agent pattern)': 'pointer.missing',
    'No approach trajectory to target': 'pointer.approach_missing',
    'Mouse movement lacks natural micro-tremor': 'pointer.low_tremor',
    'Mouse path to target is unnaturally direct': 'pointer.direct_approach',
  },
  behavioral: {
    'Zero mouse, touch, or keyboard events recorded': 'input.missing',
    'Mouse velocity too consistent': 'pointer.consistent_velocity',
    'Mouse movements too straight': 'pointer.straight_motion',
  },
  headless: {
    'WebDriver detected': 'webdriver.detected',
  },
  // CDP reasons append the reported driver labels after a colon.
  cdp: {
    'CDP automation detected': 'cdp.known_driver',
    'Multiple CDP indicators': 'cdp.multiple_indicators',
    'CDP indicator': 'cdp.single_indicator',
  },
};

const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const context = {
  ip: '203.0.113.9',
  siteKey: 'parity-fixture',
  userAgent,
  headers: {
    'user-agent': userAgent,
    accept: 'text/html',
    'accept-language': 'en-US,en;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
  },
  pow: { provided: true, valid: true, serverElapsed: 3000 },
};
const ordinaryPointer = {
  totalPoints: 80,
  trajectoryLength: 350,
  approachPoints: 12,
  microTremorScore: 0.6,
  overshootCorrections: 3,
};

function getReasonIds(detections, label) {
  return detections.flatMap(({ category, reason }) => {
    if (!Object.hasOwn(reasonIds, category)) return [];
    const message = category === 'cdp' ? reason.split(': ', 1)[0] : reason;
    assert.ok(Object.hasOwn(reasonIds[category], message), label + ' unmapped reason: ' + reason);
    return [reasonIds[category][message]];
  }).sort();
}

function scoreReference(detections) {
  const categories = reference.calculateCategoryScores(detections);
  return reference.applyCorroborationFloor(
    reference.applyDispositiveFloor(reference.calculateFinalScore(categories), detections),
    detections,
  );
}

function referenceRecommendation(score) {
  return score < 0.3 ? 'allow' : score < 0.6 ? 'challenge' : 'block';
}

function withOrdinaryBrowser(signals) {
  return {
    ...signals,
    environmental: {
      navigator: { platform: 'MacIntel', maxTouchPoints: 0 },
      ...signals.environmental,
      automationFlags: { chrome: true, plugins: 5, platform: 'MacIntel', ...signals.environmental?.automationFlags },
    },
  };
}

function compareSignalFixture(name, signals, referenceDetections, expectedIds, decisions) {
  const verdict = new embedded.DetectionEngine().score(signals, context);
  const expectedOrder = [...expectedIds].sort();

  assert.deepEqual(getReasonIds(verdict.detections, name + ' (Node)'), expectedOrder, name + ' (Node) reason IDs');
  assert.deepEqual(getReasonIds(referenceDetections, name + ' (FCaptcha)'), expectedOrder, name + ' (FCaptcha) reason IDs');
  assert.equal(verdict.recommendation, decisions.node, name + ' (Node) recommendation');
  assert.equal(referenceRecommendation(scoreReference(referenceDetections)), decisions.fcaptcha, name + ' (FCaptcha) recommendation');
}

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

  const referenceScore = scoreReference(detections);
  const recommendation = referenceRecommendation(referenceScore);
  assertOutcome(referenceScore, recommendation, fixture.reference, name + ' (FCaptcha)');
  console.log(name + ' — Node ' + fixture.embedded.recommendation + ', FCaptcha ' + recommendation);
}

assert.equal(inputModality.reference.commit, fixtures.reference.commit, 'Use the same FCaptcha commit for input-modality fixtures');
for (const { name, behavioral, reasonIds: expectedIds } of inputModality.cases) {
  const signals = withOrdinaryBrowser({ behavioral });
  const detections = [...reference.detectVisionAI(signals), ...reference.detectBehavioral(signals)];
  compareSignalFixture(name, signals, detections, expectedIds, { node: 'allow', fcaptcha: 'allow' });
  console.log(name + ' — matching reason IDs and allow outcomes');
}

for (const { name, environmental, referenceFloor, reasonIds: expectedIds, decisions } of fixtures.decisiveFloorCases) {
  if (referenceFloor === undefined) continue;
  const signals = withOrdinaryBrowser({ environmental, behavioral: ordinaryPointer });
  const detections = [...reference.detectHeadless(signals, userAgent), ...reference.detectCDP(signals)];
  const floor = reference.applyDispositiveFloor(0, detections);
  assert.equal(floor, referenceFloor, name + ' (FCaptcha decisive floor)');
  compareSignalFixture(name, signals, detections, expectedIds, decisions);
  console.log(name + ' — FCaptcha decisive floor ' + floor);
}

for (const { name, signals: input, referenceFloor, reasonIds: expectedIds, decisions } of fixtures.corroborationFloorCases) {
  if (referenceFloor === undefined) continue;
  const signals = withOrdinaryBrowser(input);
  const detections = [
    ...reference.detectVisionAI(signals),
    ...reference.detectBehavioral(signals),
    ...reference.detectCDP(signals),
  ];
  const floor = reference.applyCorroborationFloor(0, detections);
  assert.equal(floor, referenceFloor, name + ' (FCaptcha corroboration floor)');
  compareSignalFixture(name, signals, detections, expectedIds, decisions);
  console.log(name + ' — FCaptcha corroboration floor ' + floor);
}
