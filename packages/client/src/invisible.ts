/**
 * Invisible (zero-click) session.
 *
 * Passively collects signals, optionally auto-protecting form submissions:
 * intercepts submit, scores via `/api/score`, injects a token field, and
 * resubmits. Ported from FCaptcha client.js.
 */

import { BehavioralCollector } from './collectors/behavioral';
import { EnvironmentalCollector } from './collectors/environment';
import { SensorCollector } from './collectors/sensor';
import { getFormAnalyzer } from './collectors/form';
import { TemporalCollector } from './temporal';
import { PoWManager } from './pow';
import { getServerUrl } from './config';
import { sha256 } from './sha256';
import type { CollectedSignals, InvisibleOptions, PoWSolution, VerifyResponse } from './types';

interface Listener {
  event: string;
  handler: EventListener;
  opts: AddEventListenerOptions;
}

export class InvisibleSession {
  readonly id: string;
  private options: Required<InvisibleOptions>;
  private behavioral: BehavioralCollector;
  private environmental: EnvironmentalCollector;
  private temporal: TemporalCollector;
  private sensor: SensorCollector;
  private powManager: PoWManager;
  private startTime: number;
  private lastScore: (VerifyResponse & { timestamp: number }) | null = null;
  private listeners: Listener[] = [];

  constructor(options?: InvisibleOptions) {
    this.options = Object.assign(
      {
        siteKey: null,
        serverUrl: null,
        minCollectionTime: 2000,
        autoScore: true,
        scoreThreshold: 0.5,
        powDifficulty: 3,
      },
      options,
    ) as Required<InvisibleOptions>;

    this.id = 'webdecoy_inv_' + Math.random().toString(36).slice(2, 11);
    this.behavioral = new BehavioralCollector();
    this.environmental = new EnvironmentalCollector();
    this.temporal = new TemporalCollector();
    this.sensor = new SensorCollector();
    this.powManager = new PoWManager();
    this.startTime = Date.now();

    this._init();
  }

  private _init(): void {
    this._attachListeners();

    const recordFirst = (): void => this.temporal.recordFirstInteraction();
    document.addEventListener('mousemove', recordFirst, { once: true });
    document.addEventListener('touchstart', recordFirst, { once: true });
    document.addEventListener('keydown', recordFirst, { once: true });
    document.addEventListener('scroll', recordFirst, { once: true });

    if (this.options.autoScore) this._attachToForms();

    void this._fetchChallenge();
  }

  private async _fetchChallenge(): Promise<void> {
    try {
      await this.powManager.fetchChallenge(this.options.siteKey);
    } catch (e) {
      console.warn('PoW challenge fetch failed:', e);
    }
  }

  private _attachListeners(): void {
    const handlers: Record<string, EventListener> = {
      mousemove: (e) => this.behavioral.recordMouseMove(e as MouseEvent),
      mousedown: (e) => this.behavioral.recordMouseDown(e as MouseEvent),
      mouseup: (e) => this.behavioral.recordMouseUp(e as MouseEvent),
      scroll: (e) => this.behavioral.recordScroll(e),
      keydown: (e) => this.behavioral.recordKeyEvent(e as KeyboardEvent),
      keyup: (e) => this.behavioral.recordKeyEvent(e as KeyboardEvent),
      touchmove: (e) => this.behavioral.recordTouch(e as TouchEvent),
      touchstart: (e) => this.behavioral.recordTouch(e as TouchEvent),
      pointermove: (e) => this.behavioral.recordPointer(e as PointerEvent),
      pointerdown: (e) => this.behavioral.recordPointer(e as PointerEvent),
      pointerup: (e) => this.behavioral.recordPointer(e as PointerEvent),
      focus: (e) => this.behavioral.recordFocus(e as FocusEvent),
      blur: (e) => this.behavioral.recordFocus(e as FocusEvent),
    };

    for (const [event, handler] of Object.entries(handlers)) {
      const opts: AddEventListenerOptions =
        event === 'focus' || event === 'blur' ? { passive: true, capture: true } : { passive: true };
      document.addEventListener(event, handler, opts);
      this.listeners.push({ event, handler, opts });
    }

    this.sensor.attach();
  }

  private _attachToForms(): void {
    document.addEventListener('submit', async (e) => {
      const form = e.target as HTMLFormElement;
      if (form.dataset.webdecoyIgnore) return;

      let tokenField = form.querySelector('input[name="webdecoy_token"]') as HTMLInputElement | null;
      if (!tokenField) {
        tokenField = document.createElement('input');
        tokenField.type = 'hidden';
        tokenField.name = 'webdecoy_token';
        form.appendChild(tokenField);
      }

      if (!this.lastScore || Date.now() - this.lastScore.timestamp > 60000) {
        e.preventDefault();

        try {
          const result = await this.execute(form.dataset.webdecoyAction || 'form_submit');
          tokenField.value = result.token || '';

          if (result.success) {
            form.submit();
          } else {
            document.dispatchEvent(
              new CustomEvent('webdecoy:blocked', { detail: { score: result.score, form } }),
            );
          }
        } catch (error) {
          console.error('WebDecoy captcha error:', error);
          form.submit(); // Fail open
        }
      } else {
        tokenField.value = this.lastScore.token || '';
      }
    });
  }

  async execute(action = ''): Promise<VerifyResponse> {
    const elapsed = Date.now() - this.startTime;
    if (elapsed < this.options.minCollectionTime) {
      await new Promise((r) => setTimeout(r, this.options.minCollectionTime - elapsed));
    }

    const behavioralData = this.behavioral.analyze();
    const envData = this.environmental.collect();
    const temporalData = this.temporal.collect(Date.now());

    const [rafData, asyncEnvData] = await Promise.all([
      this.environmental.measureRAFConsistency(),
      this.environmental.collectAsync(),
    ]);

    const formAnalysis = getFormAnalyzer().analyze();
    const sensorData = this.sensor.analyze();

    const signals: CollectedSignals = {
      behavioral: behavioralData,
      environmental: { ...envData, rafConsistency: rafData, ...asyncEnvData, sensor: sensorData },
      temporal: temporalData,
      formAnalysis,
      meta: {
        sessionId: this.id,
        siteKey: this.options.siteKey,
        action,
        challengeNonce: this.powManager.challenge?.nonce || null,
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        screenSize: `${screen.width}x${screen.height}`,
        viewportSize: `${window.innerWidth}x${window.innerHeight}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        sessionDuration: Date.now() - this.startTime,
        invisible: true,
      },
    };

    const signalsJson = JSON.stringify(signals);
    const signalsHash = await sha256(signalsJson);
    const powSolution = await this.powManager.solveWithSignalsHash(this.options.siteKey, signalsHash);
    const powTiming = {
      duration: powSolution.duration,
      iterations: powSolution.iterations,
      difficulty: powSolution.difficulty,
    };

    const result = await this._score(signals, action, powSolution, signalsJson, signalsHash, powTiming);
    this.lastScore = { ...result, timestamp: Date.now() };
    return result;
  }

  private async _score(
    signals: CollectedSignals,
    action: string,
    powSolution: PoWSolution | null,
    signalsJson: string | null,
    signalsHash: string | null,
    powTiming: Record<string, unknown> | null,
  ): Promise<VerifyResponse> {
    const url = this.options.serverUrl || getServerUrl();
    if (!url) return this._clientSideScore(signals);

    try {
      const response = await fetch(url + '/api/score', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteKey: this.options.siteKey,
          signals,
          signalsJson: signalsJson || null,
          action,
          powSolution: powSolution
            ? {
                challengeId: powSolution.challengeId,
                nonce: powSolution.nonce,
                hash: powSolution.hash,
                signalsHash: signalsHash || null,
              }
            : null,
          powTiming: powTiming || null,
        }),
      });
      return (await response.json()) as VerifyResponse;
    } catch {
      console.warn('WebDecoy server unavailable, using client-side scoring');
      return this._clientSideScore(signals);
    }
  }

  private _clientSideScore(signals: CollectedSignals): VerifyResponse {
    let score = 0;
    const b = signals.behavioral as Record<string, number>;
    const e = signals.environmental as Record<string, any>;
    const t = signals.temporal as Record<string, any>;
    const m = signals.meta as Record<string, any>;

    const isTouchUsr = (b.touchEvents || 0) >= 3;
    const isKbdUsr = (b.keyEvents || 0) > 0 && b.totalPoints === 0;
    if (b.totalPoints < 5 && b.trajectoryLength < 10 && !isTouchUsr && !isKbdUsr) score += 0.35;
    else if (b.totalPoints < 10 && !isTouchUsr && !isKbdUsr && b.trajectoryLength < 30) score += 0.15;

    if (b.microTremorScore < 0.2) score += 0.12;
    if (b.velocityVariance < 0.03) score += 0.1;
    if (b.totalPoints < 10 && m.sessionDuration > 5000) score += 0.08;
    if (b.scrollEvents === 0 && b.keyEvents === 0 && m.sessionDuration > 10000) score += 0.06;
    if (b.eventDeltaVariance < 3) score += 0.08;
    if (b.straightLineRatio > 0.8) score += 0.08;

    if (e.webdriver) score += 0.25;
    if (e.automationFlags && e.automationFlags.plugins === 0) score += 0.06;
    if (e.headlessIndicators && !e.headlessIndicators.hasOuterDimensions) score += 0.12;
    if (e.webglInfo && e.webglInfo.suspiciousRenderer) score += 0.1;

    if (t.pow && t.pow.duration < 30) score += 0.1;
    if (m.sessionDuration < 500) score += 0.12;
    if (m.sessionDuration < 1000 && b.totalPoints < 5) score += 0.15;

    const success = score < this.options.scoreThreshold;
    return {
      success,
      score: Math.min(1, score),
      action: m.action,
      token: success
        ? btoa(JSON.stringify({ timestamp: Date.now(), score, action: m.action, id: this.id }))
        : null,
    };
  }

  getScore(): (VerifyResponse & { timestamp: number }) | null {
    return this.lastScore;
  }

  destroy(): void {
    for (const { event, handler, opts } of this.listeners) {
      document.removeEventListener(event, handler, opts);
    }
    this.listeners = [];
    if (this.powManager) this.powManager.reset();
  }
}
