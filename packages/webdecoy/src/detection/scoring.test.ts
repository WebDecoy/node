import fixtures from './fixtures/scoring-policy.json';
import { calculateCategoryScores, calculateFinalScore, recommend } from './scoring';
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
