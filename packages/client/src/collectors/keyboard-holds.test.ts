import { BehavioralCollector } from './behavioral';

describe('CAPTCHA key-hold summaries', () => {
  let clock: jest.SpyInstance<number, []>;
  let collector: BehavioralCollector;

  beforeEach(() => {
    clock = jest.spyOn(performance, 'now');
    collector = new BehavioralCollector({ collectKeyHolds: true });
  });

  afterEach(() => clock.mockRestore());

  function record(
    target: Element,
    type: 'keydown' | 'keyup',
    at: number,
    init: KeyboardEventInit = { key: 'q', code: 'KeyQ' },
  ): void {
    clock.mockReturnValue(at);
    target.addEventListener(
      type,
      event => collector.recordKeyEvent(event as KeyboardEvent),
      { once: true },
    );
    target.dispatchEvent(new KeyboardEvent(type, init));
  }

  it('pairs overlapping keys and reports only the count and average', () => {
    const input = document.createElement('input');
    const otherKey = { key: 'r', code: 'KeyR' };
    record(input, 'keydown', 100);
    record(input, 'keydown', 110, otherKey);
    record(input, 'keydown', 130, { key: 'q', code: 'KeyQ', repeat: true });
    record(input, 'keyup', 160);
    record(input, 'keyup', 190, otherKey);

    const summary = collector.analyze();
    expect(summary).toMatchObject({ keyEvents: 5, keyHoldSamples: 2, keyHoldAvg: 70 });
    expect(JSON.stringify(summary)).not.toMatch(/KeyQ|KeyR/);

    for (let i = 0; i < 10; i++) {
      collector.recordMouseMove(new MouseEvent('mousemove', { clientX: i }));
    }
    expect(collector.analyze()).toMatchObject({ totalPoints: 10, keyHoldSamples: 2, keyHoldAvg: 70 });
  });

  it('omits textareas, passwords, modifiers and composition events', () => {
    const textarea = document.createElement('textarea');
    const password = document.createElement('input');
    password.type = 'password';
    const button = document.createElement('button');
    const modifier = { key: 'Shift', code: 'ShiftLeft' };
    const composing = { key: 'q', code: 'KeyQ', isComposing: true };

    record(textarea, 'keydown', 100);
    record(textarea, 'keyup', 150);
    record(password, 'keydown', 200);
    record(password, 'keyup', 250);
    record(button, 'keydown', 300, modifier);
    record(button, 'keyup', 350, modifier);
    record(button, 'keydown', 400, composing);
    record(button, 'keyup', 450);
    record(button, 'keydown', 500);
    record(textarea, 'keyup', 550);

    expect(collector.analyze()).toMatchObject({ keyEvents: 10 });
    expect(collector.analyze()).not.toHaveProperty('keyHoldSamples');
  });

  it('caps the number of holds in the summary', () => {
    const button = document.createElement('button');
    for (let i = 0; i < 205; i++) {
      record(button, 'keydown', i * 100);
      record(button, 'keyup', i * 100 + 65);
    }
    expect(collector.analyze()).toMatchObject({ keyHoldSamples: 200, keyHoldAvg: 65 });
  });

  it('keeps the original analysis shape for callers without key holds enabled', () => {
    collector = new BehavioralCollector();
    const button = document.createElement('button');
    record(button, 'keydown', 100);
    record(button, 'keyup', 170);
    expect(collector.analyze()).toMatchObject({ keyEvents: 2 });
    expect(collector.analyze()).not.toHaveProperty('keyHoldSamples');
  });
});
