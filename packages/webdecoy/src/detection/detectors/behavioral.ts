/** Core behavioral detection: mouse data sufficiency, velocity, timing. */

import type { Detection, Signals } from '../types';

export function detectBehavioral(signals: Signals, widgetInteraction = true): Detection[] {
  const detections: Detection[] = [];
  const b = signals.behavioral ?? {};
  const t = signals.temporal ?? {};

  // Exempt touch and keyboard-only users from mouse-movement heuristics.
  const totalPoints = b.totalPoints ?? 0;
  const trajectory = b.trajectoryLength ?? 0;
  const touchEvts = b.touchEvents ?? 0;
  const keyEvts = b.keyEvents ?? 0;
  const isTouchUsr = touchEvts >= 3;
  const isKbdUser = keyEvts >= 2 && totalPoints === 0;

  if (totalPoints === 0 && !isTouchUsr && !isKbdUser) {
    detections.push({
      category: 'behavioral',
      score: 0.8,
      confidence: 0.9,
      reason: 'Zero mouse, touch, or keyboard events recorded',
    });
  } else if (totalPoints < 10 && !isTouchUsr && !isKbdUser && trajectory < 30) {
    detections.push({
      category: 'behavioral',
      score: 0.6,
      confidence: 0.7,
      reason: 'Insufficient mouse movement before interaction',
    });
  }

  const velVar = b.velocityVariance ?? 1;
  if (velVar < 0.02 && trajectory > 50) {
    detections.push({
      category: 'behavioral',
      score: 0.6,
      confidence: 0.6,
      reason: 'Mouse velocity too consistent',
    });
  }

  const overshoots = b.overshootCorrections ?? 0;
  if (widgetInteraction && overshoots === 0 && trajectory > 200) {
    detections.push({
      category: 'behavioral',
      score: 0.4,
      confidence: 0.4,
      reason: 'No overshoot corrections on long trajectory',
    });
  }

  const interactionTime = b.interactionDuration ?? 1000;
  if (interactionTime > 0 && interactionTime < 200) {
    detections.push({
      category: 'behavioral',
      score: 0.7,
      confidence: 0.7,
      reason: 'Interaction completed too quickly',
    });
  } else if (widgetInteraction && interactionTime > 60000) {
    detections.push({
      category: 'captcha_farm',
      score: 0.3,
      confidence: 0.3,
      reason: 'Unusually long interaction time',
    });
  }

  const firstInt = t.pageLoadToFirstInteraction;
  if (firstInt !== null && firstInt !== undefined && firstInt > 0 && firstInt < 100) {
    detections.push({
      category: 'behavioral',
      score: 0.5,
      confidence: 0.5,
      reason: 'First interaction too soon after page load',
    });
  }

  const eventRate = b.mouseEventRate ?? 60;
  if (eventRate > 200) {
    detections.push({
      category: 'behavioral',
      score: 0.6,
      confidence: 0.5,
      reason: 'Mouse event rate abnormally high',
    });
  } else if (eventRate > 0 && eventRate < 10) {
    detections.push({
      category: 'behavioral',
      score: 0.4,
      confidence: 0.4,
      reason: 'Mouse event rate abnormally low',
    });
  }

  const straight = b.straightLineRatio ?? 0;
  if (straight > 0.8 && trajectory > 100) {
    detections.push({
      category: 'behavioral',
      score: 0.5,
      confidence: 0.5,
      reason: 'Mouse movements too straight',
    });
  }

  const dirChanges = b.directionChanges ?? 10;
  if (totalPoints > 50 && dirChanges < 3) {
    detections.push({
      category: 'behavioral',
      score: 0.4,
      confidence: 0.4,
      reason: 'Too few direction changes',
    });
  }

  return detections;
}
