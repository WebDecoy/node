import type { Detection } from '../types';

/** Record an ordinary detection and make it available to the optional policy comparison. */
export function addCorroboratingDetection(
  detections: Detection[],
  corroborating: Detection[] | undefined,
  detection: Detection,
): void {
  detections.push(detection);
  corroborating?.push(detection);
}
