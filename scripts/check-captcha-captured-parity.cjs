/**
 * Replay a small, labeled slice of FCaptcha's captured browser corpus through
 * the embedded Node engine and the pinned FCaptcha detector modules.
 */
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { basename, join, resolve } = require('node:path');

const manifest = require('../packages/webdecoy/src/detection/fixtures/captured-corpus.json');
const scoringPolicy = require('../packages/webdecoy/src/detection/fixtures/scoring-policy.json');
const enginePath = process.argv[2];
const detectionPath = process.argv[3];
const inputForensicsPath = process.argv[4];
const corpusDir = process.argv[5];
assert.ok(enginePath, 'Pass the pinned FCaptcha server-node/engine.js path');
assert.ok(detectionPath, 'Pass the pinned FCaptcha server-node/detection.js path');
assert.ok(inputForensicsPath, 'Pass the pinned FCaptcha server-node/inputforensics.js path');
assert.ok(corpusDir, 'Pass a directory containing the pinned captured corpus files');
assert.equal(
  manifest.reference.commit,
  scoringPolicy.reference.commit,
  'Use one pinned FCaptcha commit'
);

function assertDigest(path, expected, label) {
  const hash = createHash('sha256')
    .update(readFileSync(resolve(path)))
    .digest('hex');
  assert.equal(
    hash,
    expected,
    'Use pinned ' + label + ' from FCaptcha ' + manifest.reference.commit
  );
}

assertDigest(enginePath, scoringPolicy.reference.engineSha256, 'engine.js');
assertDigest(detectionPath, scoringPolicy.reference.detectionSha256, 'detection.js');
assertDigest(inputForensicsPath, scoringPolicy.reference.inputForensicsSha256, 'inputforensics.js');

const reference = require(resolve(enginePath));
const referenceDetection = require(resolve(detectionPath));
const referenceInputForensics = require(resolve(inputForensicsPath));
const embedded = require('../packages/webdecoy/dist/index.js');

const DEFAULT_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

function readSamples(entry) {
  const path = join(resolve(corpusDir), basename(entry.path));
  const body = readFileSync(path);
  assert.equal(
    createHash('sha256').update(body).digest('hex'),
    entry.sha256,
    'Use pinned ' + entry.path + ' from FCaptcha ' + manifest.reference.commit
  );
  const samples = JSON.parse(body);
  assert.ok(Array.isArray(samples) && samples.length > 0, entry.path + ' must contain samples');
  return samples;
}

function lowerCaseHeaders(headers = {}) {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])
  );
}

const exactReasonIds = new Map(
  Object.entries({
    'automation\0JS execution unusually fast': 'timing.js_execution_fast',
    'automation\0RequestAnimationFrame timing too consistent': 'timing.raf_consistent',
    'behavioral\0First interaction too soon after page load': 'input.first_interaction_early',
    'behavioral\0Interaction completed too quickly': 'interaction.too_fast',
    'behavioral\0Keyboard-only input has unusually short key holds': 'typing.short_holds',
    'behavioral\0Mouse movements too straight': 'pointer.straight_motion',
    'behavioral\0No overshoot corrections on long trajectory': 'pointer.overshoot_missing',
    'behavioral\0Typing cadence is mechanical (inter-key and hold both below human range)':
      'typing.mechanical_cadence',
    'behavioral\0Zero mouse, touch, or keyboard events recorded': 'input.missing',
    'bot\0Keystroke cadence analysis indicates non-human typing pattern':
      'typing.non_human_cadence',
    'bot\0UA claims Chrome but window.chrome missing': 'browser.chrome_object_missing',
    'cdp\0Pointer moves never coalesced across many samples (synthetic/CDP input)':
      'pointer.uncoalesced',
    'headless\0No browser plugins detected': 'plugin.none',
    'headless\0No local IP addresses detected via WebRTC': 'webrtc.local_ip_missing',
    'headless\0Notification permission contradicts Permissions API (headless/stealth tell)':
      'notifications.permission_contradiction',
    'headless\0Notifications pre-denied': 'notifications.pre_denied',
    'headless\0Software WebGL renderer detected': 'webgl.software_renderer',
    'headless\0Software/virtualized WebGL renderer detected': 'webgl.software_renderer',
    'headless\0Viewport equals window size': 'viewport.exact_window',
    'headless\0WebDriver detected': 'webdriver.detected',
    'vision_ai\0Mouse movement lacks natural micro-tremor': 'pointer.low_tremor',
    'vision_ai\0Mouse path to target is unnaturally direct': 'pointer.direct_approach',
    'vision_ai\0No approach trajectory to target': 'pointer.approach_missing',
    'vision_ai\0No mouse movement detected before click (AI agent pattern)': 'pointer.missing',
  })
);

const patternedReasonIds = [
  [
    'bot',
    /^First interaction too fast after page load \(\d+ms\)$/,
    'timing.first_interaction_fast',
  ],
  ['bot', /^Textarea ".+" has unnaturally consistent typing rhythm$/, 'typing.consistent_rhythm'],
  [
    'bot',
    /^Textarea ".+" typing speed impossibly fast \([\d.]+ms\/key\)$/,
    'typing.impossibly_fast',
  ],
];

function getReasonIds(detections, label) {
  return detections
    .map(({ category, reason }) => {
      const exact = exactReasonIds.get(category + '\0' + reason);
      if (exact) return exact;
      const patterned = patternedReasonIds.find(
        ([expectedCategory, pattern]) => category === expectedCategory && pattern.test(reason)
      );
      assert.ok(patterned, label + ' unmapped reason: ' + category + ': ' + reason);
      return patterned[2];
    })
    .sort();
}

function assertOutcome(outcome, expected, label) {
  assert.equal(outcome.recommendation, expected.recommendation, label + ' recommendation');
  assert.equal(outcome.score < 0.5, expected.success, label + ' success');
}

function referenceVerdict(sample, headers, userAgent) {
  const signals = structuredClone(sample.signals);
  reference.setInteractionMode(signals, sample.capture?.endpoint !== '/api/score');
  const detections = [
    ...reference.detectVisionAI(signals),
    ...reference.detectHeadless(signals, userAgent),
    ...reference.detectStealthArtifacts(signals),
    ...reference.detectAutomation(signals),
    ...reference.detectCDP(signals),
    ...reference.detectBehavioral(signals),
    ...referenceInputForensics.detectInputForensics(signals),
    ...reference.detectTouchAuthenticity(signals, userAgent),
    ...reference.detectSensorEntropy(signals, userAgent),
    ...reference.detectTouchKinematics(signals),
    ...referenceDetection.analyzeHeaders(headers),
    ...referenceDetection.checkBrowserConsistency(userAgent, signals),
    ...referenceDetection.checkDeclaredAIAgent(userAgent, headers),
  ];
  if (signals.formAnalysis) {
    const behavioral = signals.behavioral || {};
    const humanPresent = (behavioral.totalPoints ?? 0) >= 5 || (behavioral.touchEvents ?? 0) >= 1;
    detections.push(
      ...referenceDetection.analyzeFormInteraction(signals.formAnalysis, { humanPresent })
    );
  }
  detections.push(...referenceDetection.analyzeAdvancedSignals(signals, userAgent));
  const categoryScores = reference.calculateCategoryScores(detections);
  const score = reference.applyCorroborationFloor(
    reference.applyDispositiveFloor(reference.calculateFinalScore(categoryScores), detections),
    detections
  );
  return {
    score,
    recommendation: score < 0.3 ? 'allow' : score < 0.6 ? 'challenge' : 'block',
    detections,
  };
}

const samples = manifest.files.flatMap(readSamples);
assert.equal(samples.length, 8, 'Captured parity slice sample count');
assert.equal(
  samples.filter(({ label }) => label === 'human').length,
  4,
  'Captured human control count'
);
assert.equal(samples.filter(({ label }) => label === 'agent').length, 4, 'Captured agent count');
assert.deepEqual(
  Object.keys(manifest.expected).sort(),
  samples.map(({ id }) => id).sort(),
  'Every captured sample has exactly one expected result'
);

for (const [index, sample] of samples.entries()) {
  assert.equal(sample.provenance, 'captured', sample.id + ' provenance');
  const headers = lowerCaseHeaders({
    'user-agent': DEFAULT_UA,
    'accept-language': 'en-US,en;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    ...sample.headers,
  });
  const userAgent = headers['user-agent'];
  const context = {
    ip: '192.0.2.' + (index + 1),
    siteKey: 'captured-parity-' + index,
    userAgent,
    headers,
    widgetInteraction: sample.capture?.endpoint !== '/api/score',
  };
  let comparison;
  const node = new embedded.DetectionEngine({
    requirePoW: false,
    onScoringComparison(value) {
      comparison = value;
    },
  }).score(structuredClone(sample.signals), context);
  const enforced = new embedded.DetectionEngine({
    requirePoW: false,
    scoringPolicy: 'noisy-or-floors-v1',
  }).score(structuredClone(sample.signals), context);
  const fcaptcha = referenceVerdict(sample, headers, userAgent);
  const expected = manifest.expected[sample.id];
  assert.ok(comparison, sample.id + ' emitted a candidate scoring comparison');
  assertOutcome(node, expected.node, sample.id + ' (Node current)');
  assertOutcome(comparison.candidate, expected.candidate, sample.id + ' (Node candidate)');
  assertOutcome(enforced, expected.candidate, sample.id + ' (Node enforced)');
  assertOutcome(fcaptcha, expected.reference, sample.id + ' (FCaptcha)');
  assert.ok(
    Math.abs(enforced.score - comparison.candidate.score) < 1e-10,
    sample.id + ' enforced score matches the observed candidate'
  );
  assert.deepEqual(
    getReasonIds(node.detections, sample.id + ' (Node)'),
    [...expected.node.reasonIds].sort(),
    sample.id + ' (Node) reason IDs'
  );
  assert.deepEqual(
    getReasonIds(fcaptcha.detections, sample.id + ' (FCaptcha)'),
    [...expected.reference.reasonIds].sort(),
    sample.id + ' (FCaptcha) reason IDs'
  );
  console.log(
    sample.id +
      ' — Node ' +
      node.recommendation +
      ', enforced ' +
      enforced.recommendation +
      ', FCaptcha ' +
      fcaptcha.recommendation
  );
}
