/**
 * Checkbox captcha widget ("I'm not a robot").
 *
 * Collects signals on click, hashes them, binds them into a PoW solution, and
 * submits to the server's `/api/verify`. Falls back to a lightweight local
 * verdict when no server is configured. Ported from FCaptcha client.js.
 */

import { BehavioralCollector } from './collectors/behavioral';
import { EnvironmentalCollector } from './collectors/environment';
import { SensorCollector } from './collectors/sensor';
import { getFormAnalyzer } from './collectors/form';
import { TemporalCollector } from './temporal';
import { getPoWManager, type PoWManager } from './pow';
import { getServerUrl } from './config';
import { sha256 } from './sha256';
import type { CollectedSignals, PoWSolution, VerifyResponse, WidgetOptions } from './types';

export class CaptchaWidget {
  readonly id: string;
  private container: HTMLElement;
  private options: Required<Pick<WidgetOptions, 'theme' | 'size' | 'powDifficulty'>> & WidgetOptions;
  private behavioral: BehavioralCollector;
  private environmental: EnvironmentalCollector;
  private temporal: TemporalCollector;
  private sensor: SensorCollector;
  private powManager: PoWManager;
  private token: string | null = null;
  private verified = false;

  private checkbox!: HTMLElement;
  private spinner!: HTMLElement;
  private label!: HTMLElement;

  constructor(container: string | HTMLElement, options?: WidgetOptions) {
    const el = typeof container === 'string' ? document.getElementById(container) : container;
    if (!el) throw new Error('WebDecoy captcha: container element not found');
    this.container = el;

    this.options = Object.assign(
      {
        siteKey: null,
        theme: 'light' as const,
        size: 'normal' as const,
        callback: null,
        errorCallback: null,
        expiredCallback: null,
        powDifficulty: 4,
      },
      options,
    );

    this.id = 'webdecoy_' + Math.random().toString(36).slice(2, 11);
    this.behavioral = new BehavioralCollector();
    this.environmental = new EnvironmentalCollector();
    this.temporal = new TemporalCollector();
    this.sensor = new SensorCollector();
    this.powManager = getPoWManager();

    this._init();
  }

  private _init(): void {
    this._createWidget();
    this._attachListeners();
    void this._fetchChallenge();
  }

  private async _fetchChallenge(): Promise<void> {
    try {
      await this.powManager.fetchChallenge(this.options.siteKey);
    } catch (e) {
      console.warn('PoW challenge fetch failed:', e);
    }
  }

  private _createWidget(): void {
    const isDark = this.options.theme === 'dark';

    this.container.innerHTML = `
      <div class="webdecoy-widget ${isDark ? 'webdecoy-dark' : ''}" id="${this.id}">
        <style>
          .webdecoy-widget {
            font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background: ${isDark ? '#1e1e1e' : '#fafafa'};
            border: 1px solid ${isDark ? '#424242' : '#d3d3d3'};
            border-radius: 6px;
            padding: 12px 16px;
            display: inline-flex;
            align-items: center;
            gap: 12px;
            min-width: 280px;
            box-sizing: border-box;
            user-select: none;
          }
          .webdecoy-checkbox {
            width: 24px; height: 24px;
            border: 2px solid ${isDark ? '#555' : '#c1c1c1'};
            border-radius: 4px; cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            background: ${isDark ? '#252525' : '#fff'};
            transition: all 0.15s ease; flex-shrink: 0;
          }
          .webdecoy-checkbox:hover { border-color: #00bcd4; }
          .webdecoy-checkbox.loading { border-color: #00bcd4; }
          .webdecoy-checkbox.verified { background: #4caf50; border-color: #4caf50; }
          .webdecoy-checkbox.failed { background: #f44336; border-color: #f44336; }
          .webdecoy-spinner {
            width: 16px; height: 16px;
            border: 2px solid ${isDark ? '#555' : '#e0e0e0'};
            border-top-color: #00bcd4; border-radius: 50%;
            animation: webdecoy-spin 0.8s linear infinite;
          }
          @keyframes webdecoy-spin { to { transform: rotate(360deg); } }
          .webdecoy-checkmark { display: none; color: white; font-size: 14px; font-weight: bold; }
          .webdecoy-checkbox.verified .webdecoy-checkmark { display: block; }
          .webdecoy-x { display: none; color: white; font-size: 14px; font-weight: bold; }
          .webdecoy-checkbox.failed .webdecoy-x { display: block; }
          .webdecoy-label { color: ${isDark ? '#e0e0e0' : '#555'}; font-size: 14px; flex-grow: 1; }
          .webdecoy-branding { display: flex; flex-direction: column; align-items: flex-end; gap: 2px; flex-shrink: 0; }
          .webdecoy-brand { font-size: 11px; font-weight: 600; color: #ff2a6d; letter-spacing: 0.5px; }
        </style>
        <div class="webdecoy-checkbox" role="checkbox" aria-checked="false" tabindex="0">
          <div class="webdecoy-spinner" style="display: none;"></div>
          <span class="webdecoy-checkmark">✓</span>
          <span class="webdecoy-x">✕</span>
        </div>
        <span class="webdecoy-label">I'm not a robot</span>
        <div class="webdecoy-branding">
          <span class="webdecoy-brand">WebDecoy</span>
        </div>
      </div>
    `;

    this.checkbox = this.container.querySelector('.webdecoy-checkbox') as HTMLElement;
    this.spinner = this.container.querySelector('.webdecoy-spinner') as HTMLElement;
    this.label = this.container.querySelector('.webdecoy-label') as HTMLElement;
  }

  private _attachListeners(): void {
    document.addEventListener('mousemove', (e) => this.behavioral.recordMouseMove(e), { passive: true });
    document.addEventListener('mousedown', (e) => this.behavioral.recordMouseDown(e), { passive: true });
    document.addEventListener('mouseup', (e) => this.behavioral.recordMouseUp(e), { passive: true });
    document.addEventListener('scroll', (e) => this.behavioral.recordScroll(e), { passive: true });
    document.addEventListener('keydown', (e) => this.behavioral.recordKeyEvent(e), { passive: true });
    document.addEventListener('keyup', (e) => this.behavioral.recordKeyEvent(e), { passive: true });
    document.addEventListener('touchstart', (e) => this.behavioral.recordTouch(e), { passive: true });
    document.addEventListener('touchmove', (e) => this.behavioral.recordTouch(e), { passive: true });
    document.addEventListener('pointermove', (e) => this.behavioral.recordPointer(e), { passive: true });
    document.addEventListener('pointerdown', (e) => this.behavioral.recordPointer(e), { passive: true });
    document.addEventListener('pointerup', (e) => this.behavioral.recordPointer(e), { passive: true });
    document.addEventListener('focus', (e) => this.behavioral.recordFocus(e), { passive: true, capture: true });
    document.addEventListener('blur', (e) => this.behavioral.recordFocus(e), { passive: true, capture: true });

    this.sensor.attach();

    const recordFirst = (): void => this.temporal.recordFirstInteraction();
    document.addEventListener('mousemove', recordFirst, { once: true });
    document.addEventListener('touchstart', recordFirst, { once: true });
    document.addEventListener('keydown', recordFirst, { once: true });

    this.checkbox.addEventListener('click', (e) => void this._handleClick(e));
    this.checkbox.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        void this._handleClick(e);
      }
    });
  }

  private async _handleClick(e: MouseEvent | KeyboardEvent): Promise<void> {
    if (this.verified || this.checkbox.classList.contains('loading')) return;

    const clickTime = performance.now();
    const rect = this.checkbox.getBoundingClientRect();

    this.checkbox.classList.add('loading');
    this.spinner.style.display = 'block';
    this.label.textContent = 'Verifying...';

    try {
      const behavioralData = this.behavioral.analyze();
      const clickX = 'clientX' in e ? e.clientX : rect.left;
      const clickY = 'clientY' in e ? e.clientY : rect.top;
      const clickData = this.behavioral.analyzeClick(clickX, clickY, rect);
      const envData = this.environmental.collect();

      const [rafData, asyncEnvData] = await Promise.all([
        this.environmental.measureRAFConsistency(),
        this.environmental.collectAsync(),
      ]);

      const temporalData = this.temporal.collect(clickTime);
      const formAnalysis = getFormAnalyzer().analyze();
      const sensorData = this.sensor.analyze();

      const signals: CollectedSignals = {
        behavioral: { ...behavioralData, ...clickData },
        environmental: { ...envData, rafConsistency: rafData, ...asyncEnvData, sensor: sensorData },
        temporal: temporalData,
        formAnalysis,
        meta: {
          widgetId: this.id,
          siteKey: this.options.siteKey,
          challengeNonce: this.powManager.challenge?.nonce || null,
          timestamp: Date.now(),
          userAgent: navigator.userAgent,
          screenSize: `${screen.width}x${screen.height}`,
          viewportSize: `${window.innerWidth}x${window.innerHeight}`,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
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

      const result = await this._verify(signals, powSolution, signalsJson, signalsHash, powTiming);

      if (result.success) {
        this._showSuccess(result.token ?? '');
      } else {
        this._showFailure(result.message ?? undefined);
      }
    } catch (error) {
      console.error('WebDecoy captcha error:', error);
      this._showFailure('Verification failed. Please try again.');
    }
  }

  private async _verify(
    signals: CollectedSignals,
    powSolution: PoWSolution | null,
    signalsJson: string | null,
    signalsHash: string | null,
    powTiming: Record<string, unknown> | null,
  ): Promise<VerifyResponse> {
    const serverUrl = getServerUrl();
    if (!serverUrl) return this._clientSideVerify(signals);

    try {
      const response = await fetch(serverUrl + '/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteKey: this.options.siteKey,
          signals,
          signalsJson: signalsJson || null,
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
      console.warn('Server unavailable, using client-side verification');
      return this._clientSideVerify(signals);
    }
  }

  private _clientSideVerify(signals: CollectedSignals): VerifyResponse {
    let score = 0;
    // Loosely-typed fallback scorer over collected signals.
    const b = signals.behavioral as Record<string, number>;
    const e = signals.environmental as Record<string, any>;
    const t = signals.temporal as Record<string, any>;

    const isTouchUser = (b.touchEvents || 0) >= 3;
    const isKbdUser = (b.keyEvents || 0) > 0 && b.totalPoints === 0;
    if (b.totalPoints < 5 && b.trajectoryLength < 10 && !isTouchUser && !isKbdUser) score += 0.35;
    else if (b.totalPoints < 10 && !isTouchUser && !isKbdUser && b.trajectoryLength < 30) score += 0.15;

    if (b.microTremorScore < 0.2) score += 0.12;
    if (b.velocityVariance < 0.03) score += 0.1;
    if (b.explorationRatio < 0.05) score += 0.08;
    if (b.overshootCorrections === 0 && b.trajectoryLength > 100) score += 0.05;
    if (b.clickPrecision < 2) score += 0.05;
    if (b.straightLineRatio > 0.8) score += 0.08;
    if (b.microMovements < 5 && b.totalPoints > 50) score += 0.06;

    if (e.webdriver) score += 0.25;
    if (e.automationFlags && e.automationFlags.plugins === 0) score += 0.05;
    if (e.webglInfo && e.webglInfo.suspiciousRenderer) score += 0.1;
    if (e.headlessIndicators && !e.headlessIndicators.hasOuterDimensions) score += 0.12;
    if (e.headlessIndicators && e.headlessIndicators.innerEqualsOuter) score += 0.05;

    if (t.pow && t.pow.duration < 50) score += 0.1;
    if (b.eventDeltaVariance < 3) score += 0.08;
    if (b.interactionDuration < 300) score += 0.07;

    const passed = score < 0.5;
    return {
      success: passed,
      score,
      token: passed ? btoa(JSON.stringify({ timestamp: Date.now(), score, id: this.id })) : null,
      message: passed ? null : 'Verification failed',
    };
  }

  private _showSuccess(token: string): void {
    this.verified = true;
    this.token = token;
    this.checkbox.classList.remove('loading');
    this.checkbox.classList.add('verified');
    this.checkbox.setAttribute('aria-checked', 'true');
    this.spinner.style.display = 'none';
    this.label.textContent = 'Verified';

    if (this.options.callback) this.options.callback(token);
    this.container.dispatchEvent(new CustomEvent('webdecoy:verified', { detail: { token } }));
  }

  private _showFailure(message?: string): void {
    this.checkbox.classList.remove('loading');
    this.checkbox.classList.add('failed');
    this.spinner.style.display = 'none';
    this.label.textContent = message || 'Verification failed';

    if (this.options.errorCallback) this.options.errorCallback(message);

    setTimeout(() => {
      this.checkbox.classList.remove('failed');
      this.label.textContent = "I'm not a robot";
    }, 3000);
  }

  getToken(): string | null {
    return this.token;
  }

  reset(): void {
    this.verified = false;
    this.token = null;
    this.behavioral = new BehavioralCollector();
    this.temporal = new TemporalCollector();
    if (this.sensor) this.sensor.detach();
    this.sensor = new SensorCollector();
    this.sensor.attach();
    this.powManager.reset();
    this.checkbox.classList.remove('verified', 'failed', 'loading');
    this.checkbox.setAttribute('aria-checked', 'false');
    this.spinner.style.display = 'none';
    this.label.textContent = "I'm not a robot";
    void this._fetchChallenge();
  }
}
