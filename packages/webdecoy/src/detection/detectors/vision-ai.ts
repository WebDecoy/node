/** Vision-AI agent detection: missing natural mouse behavior + PoW timing. */

import type { Detection, Signals } from '../types';

export function detectVisionAI(signals: Signals, widgetInteraction = true): Detection[] {
  const detections: Detection[] = [];
  const b = signals.behavioral ?? {};
  const t = signals.temporal ?? {};

  // Exempt touch and keyboard-only users from mouse-movement heuristics.
  const totalPoints = b.totalPoints ?? 0;
  const trajectory = b.trajectoryLength ?? 0;
  const approachPts = b.approachPoints ?? 0;
  const touchEvents = b.touchEvents ?? 0;
  const keyEvents = b.keyEvents ?? 0;
  const isTouchUser = touchEvents >= 3;
  const isKeyboardUser = keyEvents >= 2 && totalPoints === 0;

  if (totalPoints < 5 && trajectory < 10 && !isTouchUser && !isKeyboardUser) {
    detections.push({
      category: 'vision_ai',
      score: 0.9,
      confidence: 0.85,
      reason: 'No mouse movement detected before click (AI agent pattern)',
    });
  }

  if (widgetInteraction && approachPts === 0 && !isTouchUser && !isKeyboardUser) {
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
  if (microTremor < 0.15) {
    detections.push({
      category: 'vision_ai',
      score: 0.7,
      confidence: 0.6,
      reason: 'Mouse movement lacks natural micro-tremor',
    });
  }

  if (widgetInteraction && (b.approachDirectness ?? 0) > 0.95) {
    detections.push({
      category: 'vision_ai',
      score: 0.5,
      confidence: 0.5,
      reason: 'Mouse path to target is unnaturally direct',
    });
  }

  const precision = b.clickPrecision ?? 10;
  if (widgetInteraction && precision > 0 && precision < 2) {
    detections.push({
      category: 'vision_ai',
      score: 0.4,
      confidence: 0.5,
      reason: 'Click precision is unnaturally accurate',
    });
  }

  const exploration = b.explorationRatio ?? 0.3;
  if (widgetInteraction && exploration < 0.05 && trajectory > 50) {
    detections.push({
      category: 'vision_ai',
      score: 0.4,
      confidence: 0.4,
      reason: 'No exploratory mouse movement before click',
    });
  }

  return detections;
}
