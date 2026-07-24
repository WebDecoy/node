/**
 * @jest-environment jsdom
 *
 * Locks the behavioral-clearance contract (app repo #328, PRD FR10): what may
 * leave the browser, when a session is summarized at all, and that scripted
 * input produces measurably different aggregates than a human hand.
 */

import { BehavioralCollector } from './collectors/behavioral';
import {
  summarizeBehavior,
  hasEnoughInteraction,
  watchInteraction,
  type BehaviorAggregate,
} from './clearance-behavior';

/**
 * THE PUBLISHED COLLECTION CONTRACT. Adding a field here is a deliberate act
 * that must also update the docs page and the ingest-side struct — it is not a
 * detail to slip in, because everything on this list is data we told customers
 * (and their visitors) we collect.
 */
const ALLOWED_FIELDS = [
  'delta_var',
  'dir_changes',
  'duration_ms',
  'hold_ms',
  'keys',
  'micro_moves',
  'pointer_nonmouse',
  'samples',
  'scrolls',
  'straight_ratio',
  'touch_force_var',
  'touch_points',
  'tremor',
  'velocity_var',
];

/** A human-ish pointer path: arcs, jitter and uneven event timing. */
function humanCollector(): BehavioralCollector {
  const c = new BehavioralCollector();
  let t = 0;
  let x = 100;
  let y = 100;
  for (let i = 0; i < 60; i++) {
    // Uneven cadence (8–40ms), curved travel, sub-pixel-scale correction.
    t += 8 + ((i * 7) % 33);
    x += Math.round(6 * Math.cos(i / 4)) + (i % 3 === 0 ? 1 : -1);
    y += Math.round(5 * Math.sin(i / 3)) + (i % 4 === 0 ? -1 : 1);
    c.mousePositions.push({ x, y, t });
    if (i > 0) {
      c.mouseVelocities.push({ v: 0.2 + (i % 5) * 0.11, t });
      c.eventDeltas.push(8 + ((i * 7) % 33));
    }
  }
  c.clickData = { x, y, button: 0, downTime: t, upTime: t + 88, holdDuration: 88 };
  return c;
}

/**
 * Scripted input: page.mouse.move(x, y, {steps: n}) — exact linear
 * interpolation on a uniform beat. Paced at 40ms/step rather than a tight loop,
 * so it clears the client-side window floor: this is the HARDER case, the one
 * that actually reaches the server and has to be scored there.
 */
function scriptedCollector(): BehavioralCollector {
  const c = new BehavioralCollector();
  for (let i = 0; i < 60; i++) {
    c.mousePositions.push({ x: 100 + i * 5, y: 100 + i * 5, t: i * 40 }); // exactly collinear
    if (i > 0) {
      c.mouseVelocities.push({ v: 7.07, t: i * 40 }); // constant speed
      c.eventDeltas.push(40); // isochronous
    }
  }
  c.clickData = { x: 395, y: 395, button: 0, downTime: 2400, upTime: 2401, holdDuration: 1 };
  return c;
}

describe('collection contract', () => {
  it('emits only the published aggregate fields', () => {
    const summary = summarizeBehavior(humanCollector()) as BehaviorAggregate;
    expect(summary).not.toBeNull();
    expect(Object.keys(summary).sort()).toEqual(ALLOWED_FIELDS);
  });

  it('carries no coordinates, key identities or replayable event stream', () => {
    const c = humanCollector();
    c.keyEvents.push({ type: 'keydown', keyLength: 1, t: 10 });
    const serialized = JSON.stringify(summarizeBehavior(c));

    // The collector holds x/y positions and a per-event delta list; none of it
    // may reach the wire. Guard on the shape, not on incidental values.
    for (const banned of ['x', 'y', 'clickData', 'eventDeltas', 'mousePositions', 'key', 'target']) {
      expect(JSON.parse(serialized)).not.toHaveProperty(banned);
    }
    // Nothing nested either — every value must be a scalar.
    for (const v of Object.values(JSON.parse(serialized))) {
      expect(['number', 'boolean']).toContain(typeof v);
    }
  });

  it('reports keystrokes as a count only', () => {
    const c = humanCollector();
    for (const key of ['p', 'a', 's', 's']) {
      c.keyEvents.push({ type: 'keydown', keyLength: key.length, t: 1 });
    }
    const summary = summarizeBehavior(c) as BehaviorAggregate;
    expect(summary.keys).toBe(4);
    expect(JSON.stringify(summary)).not.toContain('pass');
  });
});

describe('when a session is summarized', () => {
  it('declines sessions with too little interaction', () => {
    expect(summarizeBehavior(new BehavioralCollector())).toBeNull();
  });

  it('declines a keyboard-only session rather than scoring it badly', () => {
    // The accessibility case: no pointer, no touch, plenty of typing. It must
    // produce NO summary, so the mint stays clean instead of looking bot-like.
    const c = new BehavioralCollector();
    for (let i = 0; i < 50; i++) c.keyEvents.push({ type: 'keydown', keyLength: 1, t: i * 90 });
    for (let i = 0; i < 10; i++) c.scrollEvents.push({ x: 0, y: i * 40, t: i * 120 });
    expect(hasEnoughInteraction(c)).toBe(false);
    expect(summarizeBehavior(c)).toBeNull();
  });

  it('declines a short burst that would report placeholder tremor', () => {
    // Under 20 samples the collector returns a 0.5 tremor PLACEHOLDER, which
    // the server would read as genuine human tremor. Never ship it.
    const c = new BehavioralCollector();
    for (let i = 0; i < 15; i++) c.mousePositions.push({ x: i, y: i, t: i * 100 });
    expect(hasEnoughInteraction(c)).toBe(false);
    expect(summarizeBehavior(c)).toBeNull();
  });

  it('accepts a touch-only session (mobile has no mouse cadence to offer)', () => {
    const c = new BehavioralCollector();
    for (let i = 0; i < 12; i++) {
      c.touchEvents.push({
        x: 50 + i * 3, y: 200 - i * 7, t: i * 30,
        force: 0.4 + (i % 3) * 0.05, radiusX: 12, radiusY: 14,
        rotationAngle: 0, identifier: 1, touchCount: 1,
      });
    }
    const summary = summarizeBehavior(c) as BehaviorAggregate;
    expect(summary).not.toBeNull();
    expect(summary.touch_points).toBe(12);
    expect(summary.touch_force_var).toBeGreaterThan(0);
  });
});

describe('scripted vs human aggregates', () => {
  it('separates them on the tells the server scores', () => {
    const human = summarizeBehavior(humanCollector()) as BehaviorAggregate;
    const scripted = summarizeBehavior(scriptedCollector()) as BehaviorAggregate;

    // Collinearity: interpolation draws a line, a hand does not.
    expect(scripted.straight_ratio).toBeGreaterThan(0.9);
    expect(human.straight_ratio).toBeLessThan(scripted.straight_ratio);

    // Physiological tremor is present in one and absent in the other.
    expect(human.tremor).toBeGreaterThan(scripted.tremor);

    // Isochrony: a script's inter-event timing barely varies.
    expect(human.delta_var).toBeGreaterThan(scripted.delta_var);

    // Constant velocity, and a click released in the same task it was pressed.
    expect(scripted.velocity_var).toBeCloseTo(0, 5);
    expect(human.velocity_var).toBeGreaterThan(0);
    expect(scripted.hold_ms).toBeLessThan(15);
    expect(human.hold_ms).toBeGreaterThan(30);
  });
});

describe('watchInteraction', () => {
  const move = (x: number, y: number): void => {
    document.dispatchEvent(new MouseEvent('mousemove', { clientX: x, clientY: y, bubbles: true }));
  };

  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('never fires for a session that does not interact', () => {
    const onReady = jest.fn();
    const stop = watchInteraction(onReady);
    jest.advanceTimersByTime(60_000);
    expect(onReady).not.toHaveBeenCalled();
    stop();
  });

  it('stops listening once cancelled', () => {
    const onReady = jest.fn();
    const stop = watchInteraction(onReady);
    stop();
    for (let i = 0; i < 80; i++) move(i * 3, i * 2);
    jest.advanceTimersByTime(60_000);
    expect(onReady).not.toHaveBeenCalled();
  });
});
