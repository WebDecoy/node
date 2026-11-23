import type { Signals } from '../types';

const MIN_KEY_HOLD_SAMPLES = 3;
const SHORT_KEY_HOLD_MS = 20;
const MAX_KEY_HOLD_MS = 2_000;

type KeyboardModality = 'keyboard-only' | 'short-key-holds';

/** Classify pointerless keyboard input using any dwell times already collected in textareas. */
export function classifyKeyboardInput(signals: Signals): KeyboardModality | null {
  const behavioral = signals.behavioral ?? {};
  const keyEvents = behavioral.keyEvents ?? 0;
  if (!Number.isFinite(keyEvents) || keyEvents < 2 || (behavioral.totalPoints ?? 0) !== 0) {
    return null;
  }

  let count = 0;
  let duration = 0;
  for (const field of Object.values(signals.formAnalysis?.textareaKeyboard ?? {})) {
    if (!Array.isArray(field?.dwellTimes)) continue;
    for (const dwell of field.dwellTimes) {
      if (typeof dwell === 'number' && dwell > 0 && dwell < MAX_KEY_HOLD_MS) {
        count++;
        duration += dwell;
      }
    }
  }

  return count >= MIN_KEY_HOLD_SAMPLES && duration / count < SHORT_KEY_HOLD_MS
    ? 'short-key-holds'
    : 'keyboard-only';
}
