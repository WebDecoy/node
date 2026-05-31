// Local data shapes used internally by the collector.
interface MousePosition {
  x: number;
  y: number;
  t: number;
}

interface VelocitySample {
  v: number;
  t: number;
}

interface AccelerationSample {
  a: number;
  t: number;
}

interface ScrollSample {
  x: number;
  y: number;
  t: number;
}

interface KeyEventSample {
  type: string;
  keyLength: number;
  t: number;
}

interface TouchSample {
  x: number;
  y: number;
  t: number;
  force: number;
  radiusX: number;
  radiusY: number;
  rotationAngle: number;
  identifier: number;
  touchCount: number;
}

interface PointerSample {
  x: number;
  y: number;
  t: number;
  type: string;
  pressure: number;
  tiltX: number;
  tiltY: number;
  tangentialPressure: number;
  pointerType: string;
}

interface FocusEventSample {
  type: string;
  target: string | undefined;
  t: number;
}

interface ClickData {
  x: number;
  y: number;
  button: number;
  downTime: number;
  upTime?: number;
  holdDuration?: number;
}

export class BehavioralCollector {
  mousePositions: MousePosition[];
  mouseVelocities: VelocitySample[];
  mouseAccelerations: AccelerationSample[];
  scrollEvents: ScrollSample[];
  keyEvents: KeyEventSample[];
  touchEvents: TouchSample[];
  touchMultiTouchSeen: boolean;
  touchIdentifiers: Set<number>;
  pointerPoints: PointerSample[];
  focusEvents: FocusEventSample[];
  clickData: ClickData | null;
  startTime: number;
  lastMousePos: { x: number; y: number } | null;
  lastMouseTime: number | null;
  lastVelocity: number | null;
  eventDeltas: number[];

  constructor() {
    this.mousePositions = [];
    this.mouseVelocities = [];
    this.mouseAccelerations = [];
    this.scrollEvents = [];
    this.keyEvents = [];
    this.touchEvents = [];
    this.touchMultiTouchSeen = false;
    this.touchIdentifiers = new Set();
    this.pointerPoints = [];
    this.focusEvents = [];
    this.clickData = null;
    this.startTime = Date.now();
    this.lastMousePos = null;
    this.lastMouseTime = null;
    this.lastVelocity = null;
    this.eventDeltas = [];
  }

  recordMouseMove(e: MouseEvent): void {
    const now = performance.now();
    const pos: MousePosition = { x: e.clientX, y: e.clientY, t: now };

    this.mousePositions.push(pos);

    // Calculate velocity and acceleration
    if (this.lastMousePos && this.lastMouseTime) {
      const dt = now - this.lastMouseTime;
      if (dt > 0) {
        const dx = e.clientX - this.lastMousePos.x;
        const dy = e.clientY - this.lastMousePos.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const velocity = distance / dt;

        this.mouseVelocities.push({ v: velocity, t: now });
        this.eventDeltas.push(dt);

        if (this.lastVelocity !== null) {
          const acceleration = (velocity - this.lastVelocity) / dt;
          this.mouseAccelerations.push({ a: acceleration, t: now });
        }
        this.lastVelocity = velocity;
      }
    }

    this.lastMousePos = { x: e.clientX, y: e.clientY };
    this.lastMouseTime = now;

    // Limit memory usage
    if (this.mousePositions.length > 500) {
      this.mousePositions.shift();
      if (this.mouseVelocities.length > 500) this.mouseVelocities.shift();
      if (this.mouseAccelerations.length > 500) this.mouseAccelerations.shift();
    }
  }

  recordMouseDown(e: MouseEvent): void {
    this.clickData = {
      x: e.clientX,
      y: e.clientY,
      button: e.button,
      downTime: performance.now()
    };
  }

  recordMouseUp(_e: MouseEvent): void {
    if (this.clickData) {
      this.clickData.upTime = performance.now();
      this.clickData.holdDuration = this.clickData.upTime - this.clickData.downTime;
    }
  }

  recordScroll(_e: Event): void {
    this.scrollEvents.push({
      x: window.scrollX,
      y: window.scrollY,
      t: performance.now()
    });
    if (this.scrollEvents.length > 100) this.scrollEvents.shift();
  }

  recordKeyEvent(e: KeyboardEvent): void {
    this.keyEvents.push({
      type: e.type,
      keyLength: e.key ? e.key.length : 0, // Don't store actual keys
      t: performance.now()
    });
  }

  recordTouch(e: TouchEvent): void {
    const touches = (e.touches && e.touches.length) ? e.touches : e.changedTouches;
    if (!touches || touches.length === 0) return;
    if (touches.length > 1) this.touchMultiTouchSeen = true;

    const touch = touches[0] as any;
    if (typeof touch.identifier === 'number') this.touchIdentifiers.add(touch.identifier);

    this.touchEvents.push({
      x: touch.clientX,
      y: touch.clientY,
      t: performance.now(),
      force: typeof touch.force === 'number' ? touch.force : 0,
      radiusX: typeof touch.radiusX === 'number' ? touch.radiusX : 0,
      radiusY: typeof touch.radiusY === 'number' ? touch.radiusY : 0,
      rotationAngle: typeof touch.rotationAngle === 'number' ? touch.rotationAngle : 0,
      identifier: typeof touch.identifier === 'number' ? touch.identifier : -1,
      touchCount: touches.length
    });
    if (this.touchEvents.length > 500) this.touchEvents.shift();
  }

  recordPointer(e: PointerEvent): void {
    this.pointerPoints.push({
      x: e.clientX,
      y: e.clientY,
      t: performance.now(),
      type: e.type,
      pressure: typeof e.pressure === 'number' ? e.pressure : 0,
      tiltX: typeof e.tiltX === 'number' ? e.tiltX : 0,
      tiltY: typeof e.tiltY === 'number' ? e.tiltY : 0,
      tangentialPressure: typeof (e as any).tangentialPressure === 'number' ? (e as any).tangentialPressure : 0,
      pointerType: e.pointerType || 'unknown'
    });
    if (this.pointerPoints.length > 500) this.pointerPoints.shift();
  }

  recordFocus(e: FocusEvent): void {
    this.focusEvents.push({
      type: e.type,
      target: (e.target as any)?.tagName,
      t: performance.now()
    });
  }

  analyze(): Record<string, unknown> {
    const positions = this.mousePositions;
    const velocities = this.mouseVelocities;
    const accelerations = this.mouseAccelerations;

    if (positions.length < 10) {
      return this._getEmptyAnalysis();
    }

    // Velocity statistics
    let avgVelocity = 0;
    let velocityVariance = 0;
    if (velocities.length > 0) {
      const sum = velocities.reduce((acc, v) => acc + v.v, 0);
      avgVelocity = sum / velocities.length;
      velocityVariance = velocities.reduce((acc, v) => {
        return acc + Math.pow(v.v - avgVelocity, 2);
      }, 0) / velocities.length;
    }

    // Acceleration statistics
    let avgAcceleration = 0;
    let accelerationChanges = 0;
    if (accelerations.length > 0) {
      avgAcceleration = accelerations.reduce((acc, a) => acc + a.a, 0) / accelerations.length;
      for (let i = 1; i < accelerations.length; i++) {
        if (Math.sign(accelerations[i].a) !== Math.sign(accelerations[i-1].a)) {
          accelerationChanges++;
        }
      }
    }

    // Micro-tremor detection (high-frequency noise - humans shake at 3-25Hz)
    const microTremorScore = this._detectMicroTremor(positions);

    // Straight line ratio (bots often move in straight lines)
    const straightLineRatio = this._calculateStraightLineRatio(positions);

    // Micro-movements (small jitters that humans make)
    let microMovements = 0;
    for (let i = 1; i < positions.length; i++) {
      const dx = Math.abs(positions[i].x - positions[i-1].x);
      const dy = Math.abs(positions[i].y - positions[i-1].y);
      if (dx < 3 && dy < 3 && (dx > 0 || dy > 0)) {
        microMovements++;
      }
    }

    // Direction changes
    const directionChanges = this._countDirectionChanges(positions);

    // Event timing variance
    const eventDeltaVariance = this._variance(this.eventDeltas);
    const mouseEventRate = positions.length > 1 ?
      positions.length / ((positions[positions.length-1].t - positions[0].t) / 1000) : 0;

    // Calculate trajectory length
    let trajectoryLength = 0;
    for (let i = 1; i < positions.length; i++) {
      const dx = positions[i].x - positions[i-1].x;
      const dy = positions[i].y - positions[i-1].y;
      trajectoryLength += Math.sqrt(dx*dx + dy*dy);
    }

    // Touch kinematics (mobile-native behavioral signal)
    const touchAnalysis = this._analyzeTouchPoints(this.touchEvents);

    // Pointer event aggregates (stylus/pen high-entropy signal)
    const pointerAnalysis = this._analyzePointerPoints(this.pointerPoints);

    return {
      totalPoints: positions.length,
      trajectoryLength,
      avgVelocity,
      velocityVariance,
      avgAcceleration,
      accelerationChanges,
      microTremorScore,
      straightLineRatio,
      microMovements,
      directionChanges,
      eventDeltas: this.eventDeltas.slice(-50),
      eventDeltaVariance,
      mouseEventRate,
      scrollEvents: this.scrollEvents.length,
      keyEvents: this.keyEvents.length,
      touchEvents: this.touchEvents.length,
      focusEvents: this.focusEvents.length,
      clickData: this.clickData,
      interactionDuration: Date.now() - this.startTime,
      ...touchAnalysis,
      ...pointerAnalysis
    };
  }

  _analyzeTouchPoints(touches: TouchSample[]): Record<string, unknown> {
    if (!touches || touches.length === 0) {
      return {
        touchTotalPoints: 0,
        touchTrajectoryLength: 0,
        touchAvgVelocity: 0,
        touchVelocityVariance: 0,
        touchMicroTremorScore: 0,
        touchStraightLineRatio: 0,
        touchDirectionChanges: 0,
        touchForceMin: 0,
        touchForceMax: 0,
        touchForceVariance: 0,
        touchRadiusMin: 0,
        touchRadiusMax: 0,
        touchRadiusVariance: 0,
        touchMultiTouchSeen: this.touchMultiTouchSeen,
        touchUniqueIdentifiers: this.touchIdentifiers.size,
        touchForceAllZero: false,
        touchForceAllOne: false
      };
    }

    let trajLen = 0;
    const vels: number[] = [];
    for (let i = 1; i < touches.length; i++) {
      const dx = touches[i].x - touches[i-1].x;
      const dy = touches[i].y - touches[i-1].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      trajLen += dist;
      const dt = touches[i].t - touches[i-1].t;
      if (dt > 0) vels.push(dist / dt);
    }
    const avgVel = vels.length > 0 ? vels.reduce((a, b) => a + b, 0) / vels.length : 0;

    const forces = touches.map(p => p.force);
    const radii = touches.map(p => Math.max(p.radiusX || 0, p.radiusY || 0));
    const forceAllZero = forces.length > 0 && forces.every(f => f === 0);
    const forceAllOne = forces.length > 0 && forces.every(f => f === 1);

    return {
      touchTotalPoints: touches.length,
      touchTrajectoryLength: trajLen,
      touchAvgVelocity: avgVel,
      touchVelocityVariance: this._variance(vels),
      touchMicroTremorScore: this._detectMicroTremor(touches),
      touchStraightLineRatio: this._calculateStraightLineRatio(touches),
      touchDirectionChanges: this._countDirectionChanges(touches),
      touchForceMin: forces.length > 0 ? Math.min(...forces) : 0,
      touchForceMax: forces.length > 0 ? Math.max(...forces) : 0,
      touchForceVariance: this._variance(forces),
      touchRadiusMin: radii.length > 0 ? Math.min(...radii) : 0,
      touchRadiusMax: radii.length > 0 ? Math.max(...radii) : 0,
      touchRadiusVariance: this._variance(radii),
      touchMultiTouchSeen: this.touchMultiTouchSeen,
      touchUniqueIdentifiers: this.touchIdentifiers.size,
      touchForceAllZero: forceAllZero,
      touchForceAllOne: forceAllOne
    };
  }

  _analyzePointerPoints(points: PointerSample[]): Record<string, unknown> {
    if (!points || points.length === 0) {
      return {
        pointerEvents: 0,
        pointerAvgPressure: 0,
        pointerPressureVariance: 0,
        pointerMaxTilt: 0,
        pointerHasNonMouseType: false,
        pointerTypes: []
      };
    }
    const pressures = points.map(p => p.pressure);
    const avgP = pressures.length > 0 ? pressures.reduce((a, b) => a + b, 0) / pressures.length : 0;
    let maxTilt = 0;
    const types = new Set<string>();
    for (const p of points) {
      const tilt = Math.abs(p.tiltX || 0) + Math.abs(p.tiltY || 0);
      if (tilt > maxTilt) maxTilt = tilt;
      if (p.pointerType) types.add(p.pointerType);
    }
    return {
      pointerEvents: points.length,
      pointerAvgPressure: avgP,
      pointerPressureVariance: this._variance(pressures),
      pointerMaxTilt: maxTilt,
      pointerHasNonMouseType: Array.from(types).some(t => t !== 'mouse' && t !== 'unknown'),
      pointerTypes: Array.from(types)
    };
  }

  analyzeClick(clickX: number, clickY: number, targetRect: DOMRect): Record<string, unknown> {
    const positions = this.mousePositions;
    if (positions.length < 5) {
      return this._getEmptyClickAnalysis();
    }

    // Approach trajectory (last 20 points)
    const approachPoints = positions.slice(-20);

    // Click precision (distance from target center)
    const targetCenterX = targetRect.left + targetRect.width / 2;
    const targetCenterY = targetRect.top + targetRect.height / 2;
    const clickPrecision = Math.sqrt(
      Math.pow(clickX - targetCenterX, 2) +
      Math.pow(clickY - targetCenterY, 2)
    );

    // Exploration ratio (movement outside target area)
    let outsideMovement = 0;
    let totalMovement = 0;

    for (let i = 1; i < positions.length; i++) {
      const dist = Math.sqrt(
        Math.pow(positions[i].x - positions[i-1].x, 2) +
        Math.pow(positions[i].y - positions[i-1].y, 2)
      );
      totalMovement += dist;

      const inTarget = (
        positions[i].x >= targetRect.left &&
        positions[i].x <= targetRect.right &&
        positions[i].y >= targetRect.top &&
        positions[i].y <= targetRect.bottom
      );
      if (!inTarget) outsideMovement += dist;
    }

    const explorationRatio = totalMovement > 0 ? outsideMovement / totalMovement : 0;

    // Overshoot detection
    let overshoots = 0;
    let wasInTarget = false;
    let passedTarget = false;

    for (const point of approachPoints) {
      const inTarget = (
        point.x >= targetRect.left &&
        point.x <= targetRect.right &&
        point.y >= targetRect.top &&
        point.y <= targetRect.bottom
      );

      if (wasInTarget && !inTarget) passedTarget = true;
      if (passedTarget && inTarget) {
        overshoots++;
        passedTarget = false;
      }
      wasInTarget = inTarget;
    }

    // Hover time before click
    let hoverTime = 0;
    for (let i = approachPoints.length - 1; i >= 0; i--) {
      const point = approachPoints[i];
      const inTarget = (
        point.x >= targetRect.left &&
        point.x <= targetRect.right &&
        point.y >= targetRect.top &&
        point.y <= targetRect.bottom
      );
      if (inTarget && i < approachPoints.length - 1) {
        hoverTime = approachPoints[approachPoints.length - 1].t - point.t;
      } else if (!inTarget) {
        break;
      }
    }

    // Approach directness
    const directDistance = Math.sqrt(
      Math.pow(approachPoints[approachPoints.length-1].x - approachPoints[0].x, 2) +
      Math.pow(approachPoints[approachPoints.length-1].y - approachPoints[0].y, 2)
    );
    let approachPathLength = 0;
    for (let i = 1; i < approachPoints.length; i++) {
      approachPathLength += Math.sqrt(
        Math.pow(approachPoints[i].x - approachPoints[i-1].x, 2) +
        Math.pow(approachPoints[i].y - approachPoints[i-1].y, 2)
      );
    }
    const approachDirectness = approachPathLength > 0 ? directDistance / approachPathLength : 1;

    return {
      clickPrecision,
      explorationRatio,
      overshootCorrections: overshoots,
      hoverTime,
      approachDirectness,
      approachPoints: approachPoints.length
    };
  }

  _detectMicroTremor(positions: { x: number; y: number; t: number }[]): number {
    if (positions.length < 20) return 0.5;

    const windowSize = 5;
    let totalNoise = 0;

    for (let i = windowSize; i < positions.length - windowSize; i++) {
      let smoothX = 0, smoothY = 0;
      for (let j = i - windowSize; j <= i + windowSize; j++) {
        smoothX += positions[j].x;
        smoothY += positions[j].y;
      }
      smoothX /= (windowSize * 2 + 1);
      smoothY /= (windowSize * 2 + 1);

      const deviation = Math.sqrt(
        Math.pow(positions[i].x - smoothX, 2) +
        Math.pow(positions[i].y - smoothY, 2)
      );
      totalNoise += deviation;
    }

    const avgNoise = totalNoise / (positions.length - windowSize * 2);
    return Math.min(1, avgNoise / 2);
  }

  _calculateStraightLineRatio(positions: { x: number; y: number; t: number }[]): number {
    if (positions.length < 3) return 0;

    let straightSegments = 0;
    let totalSegments = 0;

    for (let i = 2; i < positions.length; i++) {
      const p1 = positions[i-2];
      const p2 = positions[i-1];
      const p3 = positions[i];

      const angle1 = Math.atan2(p2.y - p1.y, p2.x - p1.x);
      const angle2 = Math.atan2(p3.y - p2.y, p3.x - p2.x);
      const angleDiff = Math.abs(angle2 - angle1);

      totalSegments++;
      if (angleDiff < 0.1) straightSegments++;
    }

    return totalSegments > 0 ? straightSegments / totalSegments : 0;
  }

  _countDirectionChanges(positions: { x: number; y: number; t: number }[]): number {
    let changes = 0;
    for (let i = 2; i < positions.length; i++) {
      const angle1 = Math.atan2(
        positions[i-1].y - positions[i-2].y,
        positions[i-1].x - positions[i-2].x
      );
      const angle2 = Math.atan2(
        positions[i].y - positions[i-1].y,
        positions[i].x - positions[i-1].x
      );
      if (Math.abs(angle2 - angle1) > Math.PI / 6) changes++;
    }
    return changes;
  }

  _variance(arr: number[]): number {
    if (arr.length === 0) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    return arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
  }

  _getEmptyAnalysis(): Record<string, unknown> {
    return {
      totalPoints: 0, trajectoryLength: 0, avgVelocity: 0, velocityVariance: 0,
      avgAcceleration: 0, accelerationChanges: 0, microTremorScore: 0.5,
      straightLineRatio: 0, microMovements: 0, directionChanges: 0,
      eventDeltas: [], eventDeltaVariance: 0, mouseEventRate: 0,
      scrollEvents: this.scrollEvents.length, keyEvents: this.keyEvents.length,
      touchEvents: this.touchEvents.length, focusEvents: this.focusEvents.length,
      clickData: this.clickData, interactionDuration: Date.now() - this.startTime,
      ...this._analyzeTouchPoints(this.touchEvents),
      ...this._analyzePointerPoints(this.pointerPoints)
    };
  }

  _getEmptyClickAnalysis(): Record<string, unknown> {
    return {
      clickPrecision: 0, explorationRatio: 0, overshootCorrections: 0,
      hoverTime: 0, approachDirectness: 1, approachPoints: 0
    };
  }
}
