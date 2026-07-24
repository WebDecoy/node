/** Fingerprint correlation: cross-IP reuse + canvas anomalies. */

import { fnv1a64Hex } from '../../webcrypto';
import type { Detection, Signals } from '../types';
import type { FingerprintStore } from '../stores';

export function detectFingerprint(
  signals: Signals,
  ip: string,
  siteKey: string,
  store: FingerprintStore,
): Detection[] {
  const detections: Detection[] = [];
  const env = signals.environmental ?? {};
  const automation = env.automationFlags ?? {};

  const components = [
    String(env.canvasHash?.hash ?? ''),
    String(env.webglInfo?.renderer ?? ''),
    String(automation.platform ?? ''),
    String(automation.hardwareConcurrency ?? ''),
  ];
  // Correlation key only — an adversary fully controls their own signals, so
  // collision resistance buys nothing; a non-crypto hash keeps this sync and
  // edge-runtime compatible.
  const fp = fnv1a64Hex(components.join('|'));

  store.record(fp, ip, siteKey);

  if (store.getIpFpCount(ip) > 5) {
    detections.push({
      category: 'fingerprint',
      score: 0.6,
      confidence: 0.6,
      reason: 'IP has used many different fingerprints',
    });
  }

  if (store.getFpIpCount(fp, siteKey) > 10) {
    detections.push({
      category: 'fingerprint',
      score: 0.5,
      confidence: 0.5,
      reason: 'Fingerprint seen from many IPs',
    });
  }

  const canvas = env.canvasHash ?? {};
  if (canvas.error || canvas.supported === false) {
    detections.push({
      category: 'fingerprint',
      score: 0.4,
      confidence: 0.4,
      reason: 'Canvas fingerprinting blocked or failed',
    });
  }

  return detections;
}
