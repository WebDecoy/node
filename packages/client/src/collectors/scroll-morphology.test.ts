import { BehavioralCollector } from './behavioral';

it('summarizes recent scroll displacement with and without mouse samples', () => {
  const collector = new BehavioralCollector();
  const scrollX = jest.replaceProperty(window, 'scrollX', 0);
  const scrollY = jest.replaceProperty(window, 'scrollY', 0);
  try {
    collector.recordScroll(new Event('scroll'));
    expect(collector.analyze()).not.toHaveProperty('scrollMorphology');

    scrollX.replaceValue(20);
    scrollY.replaceValue(70);
    collector.recordScroll(new Event('scroll'));
    scrollY.replaceValue(30);
    collector.recordScroll(new Event('scroll'));
    expect(collector.analyze()).toMatchObject({
      scrollEvents: 3,
      scrollMorphology: { samples: 3, maxStep: 90 },
    });

    for (let i = 0; i < 10; i++) {
      collector.recordMouseMove(new MouseEvent('mousemove', { clientX: i }));
    }
    expect(collector.analyze()).toMatchObject({
      totalPoints: 10,
      scrollMorphology: { samples: 3, maxStep: 90 },
    });
  } finally {
    scrollX.restore();
    scrollY.restore();
  }
});
