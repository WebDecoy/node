import type { BehavioralSignals } from '../types';

/** Match a single touch sample with non-mouse pointer evidence when available. */
export function isTouchModality(behavioral: BehavioralSignals): boolean {
  const touchEvents = behavioral.touchEvents ?? 0;
  const hasTouchSample = touchEvents > 0 || (behavioral.touchTotalPoints ?? 0) > 0;
  return touchEvents >= 3 || (hasTouchSample && behavioral.pointerHasNonMouseType === true);
}

/** Use measured movement to put slow or steady mouse input in context. */
export function hasHumanMovementMarkers(behavioral: BehavioralSignals): boolean {
  const tremor = behavioral.microTremorScore ?? 0;
  const corrections = behavioral.overshootCorrections ?? 0;
  const changes = behavioral.directionChanges ?? 0;
  return tremor >= 0.5 && (corrections >= 1 || changes >= 10);
}
