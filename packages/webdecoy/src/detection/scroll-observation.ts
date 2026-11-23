import type { BehavioralSignals, ScrollJumpObservation } from './types';

const MAX_SCROLL_SAMPLES = 100;
const LARGE_SCROLL_STEP_PX = 400;

/** Measure large steps separately from scoring because many browser actions can move a page. */
export function observeScrollJump(behavioral?: BehavioralSignals): ScrollJumpObservation | undefined {
  const { samples, maxStep } = behavioral?.scrollMorphology ?? {};
  if (
    typeof samples !== 'number' || !Number.isInteger(samples) || samples < 2 || samples > MAX_SCROLL_SAMPLES
    || typeof maxStep !== 'number' || !Number.isFinite(maxStep) || maxStep < 0
    || (behavioral?.keyEvents ?? 0) > 0 || (behavioral?.touchEvents ?? 0) > 0
  ) return undefined;

  return {
    id: 'large-scroll-step-v1',
    mode: 'observe',
    status: maxStep > LARGE_SCROLL_STEP_PX ? 'detected' : 'clear',
    samples,
    maxStep,
  };
}
