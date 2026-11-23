/** Form-interaction analysis: credential stuffing & spam patterns. */

import type { BehavioralSignals, Detection, FormAnalysisSignals } from '../types';
import { analyzeKeystrokeCadence } from './keystroke';

export function analyzeFormInteraction(
  formAnalysis?: FormAnalysisSignals,
  behavioral?: BehavioralSignals,
): Detection[] {
  if (!formAnalysis) return [];

  const detections: Detection[] = [];
  const submit = formAnalysis.submit ?? {};

  if (submit.method === 'programmatic' || submit.method === 'programmatic_click') {
    detections.push({
      category: 'bot',
      score: 0.8,
      confidence: 0.85,
      reason: `Form submitted programmatically (${submit.method})`,
    });
  }

  if (
    submit.timeSincePageLoad !== null &&
    submit.timeSincePageLoad !== undefined &&
    submit.timeSincePageLoad < 800
  ) {
    detections.push({
      category: 'bot',
      score: 0.7,
      confidence: 0.75,
      reason: `Form submitted too quickly after page load (${Math.round(submit.timeSincePageLoad)}ms)`,
    });
  }

  const pageToFirst = formAnalysis.pageLoadToFirstInteraction;
  if (pageToFirst !== null && pageToFirst !== undefined && pageToFirst < 300) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.65,
      reason: `First interaction too fast after page load (${Math.round(pageToFirst)}ms)`,
    });
  }

  if (submit.eventsBeforeSubmit === 0 && submit.method !== 'none') {
    detections.push({
      category: 'bot',
      score: 0.9,
      confidence: 0.9,
      reason: 'Form submitted with no user interaction events',
    });
  }

  if (
    submit.eventsBeforeSubmit !== undefined &&
    submit.eventsBeforeSubmit > 0 &&
    submit.eventsBeforeSubmit < 3 &&
    submit.method !== 'none'
  ) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: `Very few events before submit (${submit.eventsBeforeSubmit})`,
    });
  }

  const textareaData = formAnalysis.textareaKeyboard;
  if (textareaData) {
    const hasPointerOrTouch = (behavioral?.totalPoints ?? 0) >= 5 || (behavioral?.touchEvents ?? 0) > 0;
    for (const [fieldId, stats] of Object.entries(textareaData)) {
      const keyCount = stats.keyCount ?? 0;
      const pasteCount = stats.pasteCount ?? 0;
      const avgKeyInterval = stats.avgKeyInterval ?? 0;
      const keyIntervalVariance = stats.keyIntervalVariance ?? 0;
      const keydownUpRatio = stats.keydownUpRatio ?? 1;

      if (pasteCount > 0 && keyCount < 5 && !hasPointerOrTouch) {
        detections.push({
          category: 'bot',
          score: 0.6,
          confidence: 0.6,
          reason: `Textarea "${fieldId}" filled mostly by paste (${pasteCount} pastes, ${keyCount} keystrokes)`,
        });
      }

      if (keyCount > 10 && keyIntervalVariance < 100) {
        detections.push({
          category: 'bot',
          score: 0.5,
          confidence: 0.55,
          reason: `Textarea "${fieldId}" has unnaturally consistent typing rhythm`,
        });
      }

      if (keyCount > 10 && avgKeyInterval > 0 && avgKeyInterval < 50) {
        detections.push({
          category: 'bot',
          score: 0.7,
          confidence: 0.7,
          reason: `Textarea "${fieldId}" typing speed impossibly fast (${Math.round(avgKeyInterval)}ms/key)`,
        });
      }

      if (keyCount > 10 && (keydownUpRatio < 0.8 || keydownUpRatio > 1.2)) {
        detections.push({
          category: 'bot',
          score: 0.4,
          confidence: 0.5,
          reason: `Textarea "${fieldId}" has abnormal keydown/keyup ratio (${keydownUpRatio.toFixed(2)})`,
        });
      }

      if (stats.noKeyboardEvents && keyCount === 0 && pasteCount === 0 && (stats.contentLength ?? 0) > 0) {
        detections.push({
          category: 'bot',
          score: 0.75,
          confidence: 0.8,
          reason: `Textarea "${fieldId}" has ${stats.contentLength} chars but no keyboard events (DOM manipulation)`,
        });
      }

      const cadenceResult = analyzeKeystrokeCadence(stats);
      if (cadenceResult) detections.push(cadenceResult);
    }
  }

  return detections;
}
