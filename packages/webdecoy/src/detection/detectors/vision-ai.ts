/** Vision-AI agent detection: missing natural mouse behavior + PoW timing. */

import type { Detection, Signals } from '../types';
import { addCorroboratingDetection } from './corroborating-detection';
import { classifyKeyboardInput } from './keyboard-input';
import { hasHumanMovementMarkers, isTouchModality } from './pointer-evidence';

export function detectVisionAI(
  signals: Signals, widgetInteraction = true, corroborating?: Detection[],
): Detection[] {
  const detections: Detection[] = [];
  const b = signals.behavioral ?? {};
  const t = signals.temporal ?? {};

  // Exempt touch and keyboard-only users from mouse-movement heuristics.
  const totalPoints = b.totalPoints ?? 0;
  const trajectory = b.trajectoryLength ?? 0;
  const approachPts = b.approachPoints ?? 0;
  const isTouchUser = isTouchModality(b);
  const isKeyboardUser = classifyKeyboardInput(signals) === 'keyboard-only';
  const usesMouse = !isTouchUser && !isKeyboardUser;

  if (totalPoints < 5 && trajectory < 10 && usesMouse) {
    detections.push({
      category: 'vision_ai',
      score: 0.9,
      confidence: 0.85,
      reason: 'No mouse movement detected before click (AI agent pattern)',
    });
  }

  if (widgetInteraction && approachPts === 0 && usesMouse) {
    detections.push({
      category: 'vision_ai',
      score: 0.7,
      confidence: 0.8,
      reason: 'No approach trajectory to target',
    });
  }

  const pow = t.pow ?? {};
  if (pow.duration && pow.iterations) {
    const expectedMin = (pow.iterations / 500000) * 1000;
    const expectedMax = (pow.iterations / 50000) * 1000;

    if (pow.duration < expectedMin * 0.5) {
      detections.push({
        category: 'vision_ai',
        score: 0.8,
        confidence: 0.7,
        reason: 'PoW completed impossibly fast',
      });
    } else if (pow.duration > expectedMax * 3) {
      detections.push({
        category: 'vision_ai',
        score: 0.6,
        confidence: 0.5,
        reason: 'PoW timing suggests external processing',
      });
    }
  }

  const microTremor = b.microTremorScore ?? 0.5;
  if (usesMouse && totalPoints >= 5 && microTremor < 0.15) {
    addCorroboratingDetection(detections, corroborating, {
      category: 'vision_ai',
      score: 0.7,
      confidence: 0.6,
      reason: 'Mouse movement lacks natural micro-tremor',
    });
  }

  if (
    widgetInteraction &&
    usesMouse &&
    approachPts >= 5 &&
    (b.approachDirectness ?? 0) > 0.95 &&
    !hasHumanMovementMarkers(b)
  ) {
    addCorroboratingDetection(detections, corroborating, {
      category: 'vision_ai',
      score: 0.5,
      confidence: 0.5,
      reason: 'Mouse path to target is unnaturally direct',
    });
  }

  const exploration = b.explorationRatio ?? 0.3;
  if (widgetInteraction && exploration < 0.05 && trajectory > 50) {
    addCorroboratingDetection(detections, corroborating, {
      category: 'vision_ai',
      score: 0.4,
      confidence: 0.4,
      reason: 'No exploratory mouse movement before click',
    });
  }

  return detections;
}
