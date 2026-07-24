/**
 * Behavioral human-likelihood for clearance minting (app repo #328, PRD FR10).
 *
 * A wd_clearance token normally says only "this is a real browser that hasn't
 * tripped deception". This module lets a session also present POSITIVE evidence
 * that a human is driving it, which the mint turns into a graded 'human-likely'
 * token — the grade a route can require for its most sensitive paths.
 *
 * WHAT LEAVES THE BROWSER (this is the whole list):
 *   counts        — how many pointer samples, scrolls, keystrokes, touches
 *   durations     — the observation window, and how long a click was held
 *   variances     — of pointer velocity, of inter-event timing, of touch force
 *   ratios        — micro-tremor and collinearity of the pointer path, 0–1
 *
 * WHAT NEVER LEAVES THE BROWSER: pointer coordinates, the keys pressed, form
 * values, element or page content, URLs, screenshots, and any kind of replayable
 * event stream. Nothing here can reconstruct what a person typed, read, clicked
 * or looked at — the aggregates describe HOW the session moved, never WHAT it
 * did. That is the whole difference between this and a session-replay vendor,
 * and it is why the collection contract is published rather than buried.
 *
 * The scoring itself is deliberately NOT done here: the browser reports
 * observations, the server decides what they earn. A client that fabricates
 * flattering aggregates gains nothing it could not gain by lying about its
 * fingerprint, and the mint caps any grade by the actor's threat score.
 */

import { BehavioralCollector } from './collectors/behavioral';

/** The wire shape posted as `behavior` on a clearance mint. */
export interface BehaviorAggregate {
  samples: number;
  duration_ms: number;
  tremor: number;
  straight_ratio: number;
  velocity_var: number;
  delta_var: number;
  dir_changes: number;
  micro_moves: number;
  hold_ms: number;
  touch_points: number;
  touch_force_var: number;
  pointer_nonmouse: boolean;
  scrolls: number;
  keys: number;
}

/**
 * Minimum pointer samples before a session is summarized at all.
 *
 * Above the collector's own 20-sample floor on purpose: below that,
 * _detectMicroTremor returns a 0.5 placeholder rather than a measurement, and
 * shipping a placeholder the server reads as real tremor would manufacture
 * human evidence out of a short mouse twitch.
 */
const MIN_POINTER_SAMPLES = 24;

/** Minimum touch points for the mobile modality (real digitizer data is dense). */
const MIN_TOUCH_POINTS = 8;

/** Minimum observation window; a burst inside a few milliseconds is not a session. */
const MIN_WINDOW_MS = 750;

/**
 * How long to keep collecting after the thresholds are first met. More
 * interaction means a better-founded summary, and the upgrade is not urgent —
 * the session already holds a valid clean token.
 */
const SETTLE_MS = 1500;

function num(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

/** The observed pointer window, measured from the samples rather than from
 *  page load — a visitor who reads for a minute and then moves the mouse has a
 *  two-second pointer window, not a sixty-second one. */
function pointerWindowMs(collector: BehavioralCollector): number {
  const p = collector.mousePositions;
  if (!p || p.length < 2) return 0;
  return Math.max(0, Math.round(p[p.length - 1].t - p[0].t));
}

/** Whether the session has enough interaction to be worth summarizing. */
export function hasEnoughInteraction(collector: BehavioralCollector): boolean {
  const pointerReady =
    collector.mousePositions.length >= MIN_POINTER_SAMPLES &&
    pointerWindowMs(collector) >= MIN_WINDOW_MS;
  const touchReady = collector.touchEvents.length >= MIN_TOUCH_POINTS;
  return pointerReady || touchReady;
}

/**
 * Reduce a collector to the published aggregate set. Returns null when the
 * session has too little interaction to describe — an unscored mint is a clean
 * token, which is exactly what a keyboard-only or assistive-technology session
 * should get rather than a low score it never earned.
 */
export function summarizeBehavior(collector: BehavioralCollector): BehaviorAggregate | null {
  if (!hasEnoughInteraction(collector)) return null;

  const a = collector.analyze();
  const click = collector.clickData;

  // Every field below is a scalar count, duration, variance or ratio. If a
  // future signal cannot be described that way, it does not belong on this wire.
  return {
    samples: num(a.totalPoints),
    duration_ms: pointerWindowMs(collector),
    tremor: num(a.microTremorScore),
    straight_ratio: num(a.straightLineRatio),
    velocity_var: num(a.velocityVariance),
    delta_var: num(a.eventDeltaVariance),
    dir_changes: num(a.directionChanges),
    micro_moves: num(a.microMovements),
    hold_ms: num(click?.holdDuration),
    touch_points: num(a.touchTotalPoints),
    touch_force_var: num(a.touchForceVariance),
    pointer_nonmouse: a.pointerHasNonMouseType === true,
    scrolls: num(a.scrollEvents),
    keys: num(a.keyEvents),
  };
}

/**
 * Watch the session until it has enough interaction to summarize, then hand the
 * aggregate over ONCE and stop listening.
 *
 * All listeners are passive (they never delay scrolling or input) and are
 * removed as soon as the summary is delivered, so the steady-state cost of a
 * cleared session is zero. A session that never interacts never fires, never
 * posts, and keeps the clean token it already has.
 *
 * Returns a cancel function for callers that unmount.
 */
export function watchInteraction(onReady: (b: BehaviorAggregate) => void): () => void {
  if (typeof document === 'undefined') return () => {};

  const collector = new BehavioralCollector();
  let settleTimer: ReturnType<typeof setTimeout> | null = null;
  let done = false;

  const handlers: Record<string, EventListener> = {
    mousemove: (e) => collector.recordMouseMove(e as MouseEvent),
    mousedown: (e) => collector.recordMouseDown(e as MouseEvent),
    mouseup: (e) => collector.recordMouseUp(e as MouseEvent),
    scroll: (e) => collector.recordScroll(e),
    keydown: (e) => collector.recordKeyEvent(e as KeyboardEvent),
    touchstart: (e) => collector.recordTouch(e as TouchEvent),
    touchmove: (e) => collector.recordTouch(e as TouchEvent),
    pointerdown: (e) => collector.recordPointer(e as PointerEvent),
  };

  const stop = (): void => {
    if (done) return;
    done = true;
    if (settleTimer) clearTimeout(settleTimer);
    for (const [event, handler] of Object.entries(handlers)) {
      document.removeEventListener(event, handler);
    }
  };

  const check = (): void => {
    if (done || settleTimer) return;
    if (!hasEnoughInteraction(collector)) return;
    // Thresholds met: collect a little longer, then deliver and detach.
    settleTimer = setTimeout(() => {
      settleTimer = null;
      const summary = summarizeBehavior(collector);
      stop();
      if (summary) onReady(summary);
    }, SETTLE_MS);
  };

  for (const [event, handler] of Object.entries(handlers)) {
    const wrapped: EventListener = (e) => {
      handler(e);
      check();
    };
    handlers[event] = wrapped;
    document.addEventListener(event, wrapped, { passive: true });
  }

  return stop;
}
