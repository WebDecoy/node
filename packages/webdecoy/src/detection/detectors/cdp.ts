/** Chrome DevTools Protocol / driver-injection detection. */

import type { Detection, Signals } from '../types';

const HIGH_CONFIDENCE_SIGNALS = ['chromedriver_cdc', 'puppeteer_eval', 'cdp_script_injection'];

export function hasDriverInjection(signals: readonly string[]): boolean {
  return signals.some((signal) => HIGH_CONFIDENCE_SIGNALS.includes(signal));
}

export function detectCDP(signals: Signals): Detection[] {
  const detections: Detection[] = [];
  const cdp = signals.environmental?.cdp ?? {};

  if (!cdp.detected) return detections;

  const signalList = cdp.signals ?? [];
  const signalCount = signalList.length;

  if (hasDriverInjection(signalList)) {
    detections.push({
      category: 'cdp',
      score: 0.9,
      confidence: 0.95,
      reason: `CDP automation detected: ${signalList.join(', ')}`,
    });
  } else if (signalCount >= 2) {
    detections.push({
      category: 'cdp',
      score: 0.8,
      confidence: 0.85,
      reason: `Multiple CDP indicators: ${signalList.join(', ')}`,
    });
  } else if (signalCount === 1) {
    detections.push({
      category: 'cdp',
      score: 0.6,
      confidence: 0.7,
      reason: `CDP indicator: ${signalList.join(', ')}`,
    });
  }

  return detections;
}
