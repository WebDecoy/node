interface MotionRecord {
  x: number;
  y: number;
  z: number;
  t: number;
}

interface OrientationRecord {
  alpha: number;
  beta: number;
  gamma: number;
  t: number;
}

interface SensorAnalysis {
  motionEventCount: number;
  motionAccelAvg: number;
  motionAccelVariance: number;
  orientationEventCount: number;
  orientationVariance: number;
  hasSensorSupport: boolean;
}

export class SensorCollector {
  motionEvents: MotionRecord[];
  orientationEvents: OrientationRecord[];
  private _motionHandler: (e: Event) => void;
  private _orientationHandler: (e: Event) => void;
  private _attached: boolean;

  constructor() {
    this.motionEvents = [];
    this.orientationEvents = [];
    this._motionHandler = (e: Event): void => this._recordMotion(e as DeviceMotionEvent);
    this._orientationHandler = (e: Event): void => this._recordOrientation(e as DeviceOrientationEvent);
    this._attached = false;
  }

  attach(): void {
    if (this._attached) return;
    this._attached = true;
    try {
      window.addEventListener('devicemotion', this._motionHandler, { passive: true });
      window.addEventListener('deviceorientation', this._orientationHandler, { passive: true });
    } catch (_e) { /* ignore */ }
  }

  detach(): void {
    if (!this._attached) return;
    this._attached = false;
    try {
      window.removeEventListener('devicemotion', this._motionHandler);
      window.removeEventListener('deviceorientation', this._orientationHandler);
    } catch (_e) { /* ignore */ }
  }

  _recordMotion(e: DeviceMotionEvent): void {
    const a = e.accelerationIncludingGravity || e.acceleration || ({} as DeviceMotionEventAcceleration);
    this.motionEvents.push({
      x: typeof a.x === 'number' ? a.x : 0,
      y: typeof a.y === 'number' ? a.y : 0,
      z: typeof a.z === 'number' ? a.z : 0,
      t: performance.now()
    });
    if (this.motionEvents.length > 300) this.motionEvents.shift();
  }

  _recordOrientation(e: DeviceOrientationEvent): void {
    this.orientationEvents.push({
      alpha: typeof e.alpha === 'number' ? e.alpha : 0,
      beta: typeof e.beta === 'number' ? e.beta : 0,
      gamma: typeof e.gamma === 'number' ? e.gamma : 0,
      t: performance.now()
    });
    if (this.orientationEvents.length > 300) this.orientationEvents.shift();
  }

  analyze(): SensorAnalysis {
    const motion = this.motionEvents;
    const orientation = this.orientationEvents;

    let motionAccelVariance = 0;
    let motionAccelAvg = 0;
    if (motion.length > 1) {
      const mags = motion.map((m) => Math.sqrt(m.x * m.x + m.y * m.y + m.z * m.z));
      motionAccelAvg = mags.reduce((a, b) => a + b, 0) / mags.length;
      motionAccelVariance = mags.reduce((s, v) => s + (v - motionAccelAvg) * (v - motionAccelAvg), 0) / mags.length;
    }

    let orientationVariance = 0;
    if (orientation.length > 1) {
      const tilts = orientation.map((o) => Math.abs(o.beta) + Math.abs(o.gamma));
      const mean = tilts.reduce((a, b) => a + b, 0) / tilts.length;
      orientationVariance = tilts.reduce((s, v) => s + (v - mean) * (v - mean), 0) / tilts.length;
    }

    return {
      motionEventCount: motion.length,
      motionAccelAvg,
      motionAccelVariance,
      orientationEventCount: orientation.length,
      orientationVariance,
      hasSensorSupport: typeof (window as any).DeviceMotionEvent !== 'undefined'
    };
  }
}
