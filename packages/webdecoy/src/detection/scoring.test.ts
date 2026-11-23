import fixtures from './fixtures/scoring-policy.json';
import {
  calculateCategoryScores,
  calculateFinalScore,
  calculateNoisyOrCategoryScores,
  recommend,
} from './scoring';
import { DEFAULT_WEIGHTS } from './weights';

describe('embedded CAPTCHA score policy', () => {
  it.each(fixtures.cases)('$name', ({ detections, embedded }) => {
    const categories = calculateCategoryScores(detections, DEFAULT_WEIGHTS);
    const score = calculateFinalScore(categories, DEFAULT_WEIGHTS);
    expect(score).toBeCloseTo(embedded.score, 10);
    expect(recommend(score)).toBe(embedded.recommendation);
    expect(score < 0.5).toBe(embedded.success);
  });
});

describe('noisy-OR score aggregation', () => {
  it.each(fixtures.cases.filter(({ name }) => [
    'ordinary input with no findings',
    'one weak behavior finding',
    'one stronger observation',
    'two observations in one category',
    'debug context contributes without corroborating',
  ].includes(name)))('matches the reference aggregation for $name', ({ detections, reference }) => {
    const categories = calculateNoisyOrCategoryScores(detections, DEFAULT_WEIGHTS);
    expect(calculateFinalScore(categories, DEFAULT_WEIGHTS)).toBeCloseTo(reference.score, 10);
  });

  it('bounds categories when evidence is oversized or invalid', () => {
    const detections = [
      { category: 'oversized', reason: 'fixture', score: 2, confidence: 1 },
      { category: 'invalid', reason: 'fixture', score: NaN, confidence: 1 },
      { category: 'invalid', reason: 'fixture', score: 0.8, confidence: Infinity },
      { category: 'invalid', reason: 'fixture', score: -1, confidence: -1 },
      { category: 'ignored', reason: 'fixture', score: 1, confidence: 1 },
    ];
    expect(calculateNoisyOrCategoryScores(detections, { oversized: 1, invalid: 1, empty: 1 }))
      .toEqual({ oversized: 1, invalid: 0, empty: 0 });
  });
});
