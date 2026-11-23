/** Per-category score aggregation and weighted totals. */

import { hasDriverInjection } from './detectors/cdp';
import type { CategoryScores, Detection, EnvironmentalSignals, Recommendation } from './types';

/** Minimum candidate score for an explicit automation declaration or driver injection. */
export function applyDecisiveScoreFloor(
  score: number,
  env: EnvironmentalSignals | undefined,
  weights: Record<string, number>,
): number {
  // The collector's top-level WebDriver flag includes indirect hints.
  const declaresWebDriver = (weights.headless ?? 0) > 0 &&
    env?.webdriver === true && env.automationFlags?.webdriver === true;
  const hasInjectedDriver = (weights.cdp ?? 0) > 0 &&
    env?.cdp?.detected === true && hasDriverInjection(env.cdp.signals ?? []);
  return declaresWebDriver || hasInjectedDriver ? Math.max(0.9, score) : score;
}

/**
 * Aggregate detections into per-category scores. Each category's score is the
 * confidence-weighted mean of its detections' scores, capped at 1.0. Categories
 * present in `weights` but with no detections are filled with 0.
 */
export function calculateCategoryScores(
  detections: Detection[],
  weights: Record<string, number>,
): CategoryScores {
  const categoryData: Record<string, Array<[number, number]>> = {};

  for (const d of detections) {
    (categoryData[d.category] ??= []).push([d.score, d.confidence]);
  }

  const result: CategoryScores = {};
  for (const [cat, scores] of Object.entries(categoryData)) {
    if (scores.length > 0) {
      const totalWeight = scores.reduce((sum, [, conf]) => sum + conf, 0);
      if (totalWeight > 0) {
        const weightedSum = scores.reduce((sum, [score, conf]) => sum + score * conf, 0);
        result[cat] = Math.min(1.0, weightedSum / totalWeight);
      }
    }
  }

  for (const cat of Object.keys(weights)) {
    if (!(cat in result)) result[cat] = 0.0;
  }

  return result;
}

/** Combine confidence-scaled evidence so adding a finding cannot lower its category score. */
export function calculateNoisyOrCategoryScores(
  detections: Detection[],
  weights: Record<string, number>,
): CategoryScores {
  const remaining = new Map<string, number>();
  for (const { category, score, confidence } of detections) {
    if (!Number.isFinite(score) || !Number.isFinite(confidence) || score <= 0 || confidence <= 0) {
      continue;
    }
    const evidence = Math.min(1, score * confidence);
    remaining.set(category, (remaining.get(category) ?? 1) * (1 - evidence));
  }

  return Object.fromEntries(
    Object.keys(weights).map((category) => [category, 1 - (remaining.get(category) ?? 1)]),
  );
}

/** Combine category scores into the final weighted score (capped at 1.0). */
export function calculateFinalScore(
  categoryScores: CategoryScores,
  weights: Record<string, number>,
): number {
  let total = 0;
  for (const [cat, weight] of Object.entries(weights)) {
    total += (categoryScores[cat] ?? 0) * weight;
  }
  return Math.min(1.0, total);
}

/** Map a final score to an action recommendation. */
export function recommend(finalScore: number): Recommendation {
  if (finalScore < 0.3) return 'allow';
  if (finalScore < 0.6) return 'challenge';
  return 'block';
}
