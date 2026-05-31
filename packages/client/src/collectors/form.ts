// FormAnalyzer: tracks form interactions, submit method, and textarea keystroke
// statistics for spam detection. Ported 1:1 from the original JavaScript source.

interface EventLogEntry {
  type: string;
  time: number;
  target: string;
}

interface TextareaStats {
  keydowns: number[];
  keyups: number[];
  intervals: number[];
  lastKeyTime: number | null;
  inputWithoutKey: number;
  pasteCount: number;
  dwellTimes: number[];
  rollovers: number;
  activeKeyCount: number;
  pendingKeydowns: number[];
}

interface SubmitData {
  method: string;
  time?: number;
  timeSincePageLoad?: number;
  timeSinceFirstInteraction?: number | null;
  timeSinceLastInteraction?: number | null;
  eventsBeforeSubmit: number;
  hadTriggerEvent: boolean;
}

export class FormAnalyzer {
  pageLoadTime: number;
  firstInteractionTime: number | null;
  lastInteractionTime: number | null;
  totalEvents: number;
  eventLog: EventLogEntry[];
  textareaStats: Map<string, TextareaStats>;
  submitData: SubmitData | null;

  constructor() {
    this.pageLoadTime = performance.now();
    this.firstInteractionTime = null;
    this.lastInteractionTime = null;
    this.totalEvents = 0;
    this.eventLog = []; // Recent events before submit
    this.textareaStats = new Map(); // Per-textarea keyboard analysis
    this.submitData = null;

    this._setupListeners();
  }

  _setupListeners(): void {
    // Track first and ongoing interactions
    const interactionEvents = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    interactionEvents.forEach((eventType) => {
      document.addEventListener(eventType, (e: Event) => this._recordInteraction(e), { passive: true });
    });

    // Track textarea keyboard patterns (spam detection)
    document.addEventListener('keydown', (e: KeyboardEvent) => this._recordTextareaKey(e), { passive: true });
    document.addEventListener('keyup', (e: KeyboardEvent) => this._recordTextareaKey(e), { passive: true });

    // Track form submissions
    document.addEventListener('submit', (e: SubmitEvent) => this._recordSubmit(e), { capture: true });

    // Track programmatic submit detection
    this._interceptFormSubmit();
  }

  _recordInteraction(e: Event): void {
    const now = performance.now();

    if (this.firstInteractionTime === null) {
      this.firstInteractionTime = now;
    }
    this.lastInteractionTime = now;
    this.totalEvents++;

    // Keep last 50 events for analysis
    this.eventLog.push({
      type: e.type,
      time: now,
      target: (e.target as Element | null)?.tagName || 'unknown'
    });
    if (this.eventLog.length > 50) {
      this.eventLog.shift();
    }
  }

  _recordTextareaKey(e: KeyboardEvent): void {
    // Only analyze textareas (safe from password manager conflicts)
    const target = e.target as (HTMLTextAreaElement & Element) | null;
    if (target?.tagName !== 'TEXTAREA') return;

    const textareaId = target.id || target.name || 'unnamed';
    if (!this.textareaStats.has(textareaId)) {
      this.textareaStats.set(textareaId, {
        keydowns: [],
        keyups: [],
        intervals: [],
        lastKeyTime: null,
        inputWithoutKey: 0,
        pasteCount: 0,
        dwellTimes: [],
        rollovers: 0,
        activeKeyCount: 0,
        pendingKeydowns: []
      });
    }

    const stats = this.textareaStats.get(textareaId) as TextareaStats;
    const now = performance.now();

    // Modifier keys excluded from dwell/rollover tracking
    const isModifier = ['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'NumLock', 'ScrollLock'].includes(e.key);

    if (e.type === 'keydown') {
      stats.keydowns.push(now);
      if (stats.lastKeyTime !== null) {
        stats.intervals.push(now - stats.lastKeyTime);
      }
      stats.lastKeyTime = now;

      // Dwell/rollover tracking (non-modifier, non-repeat only)
      if (!isModifier && !e.repeat) {
        if (stats.activeKeyCount > 0) {
          stats.rollovers++;
        }
        stats.activeKeyCount++;
        stats.pendingKeydowns.push(now);
      }

      // Limit memory
      if (stats.keydowns.length > 200) stats.keydowns.shift();
      if (stats.intervals.length > 200) stats.intervals.shift();
    } else if (e.type === 'keyup') {
      stats.keyups.push(now);
      if (stats.keyups.length > 200) stats.keyups.shift();

      // Dwell time tracking (non-modifier only)
      if (!isModifier && stats.activeKeyCount > 0) {
        stats.activeKeyCount--;
        if (stats.pendingKeydowns.length > 0) {
          const keydownTime = stats.pendingKeydowns.shift() as number;
          const dwell = now - keydownTime;
          if (dwell > 0 && dwell < 2000) {
            stats.dwellTimes.push(dwell);
            // Ring buffer: cap at 100
            if (stats.dwellTimes.length > 100) stats.dwellTimes.shift();
          }
        }
      }
    }
  }

  _interceptFormSubmit(): void {
    // Detect programmatic form.submit() calls
    const self = this;
    const originalSubmit = HTMLFormElement.prototype.submit;

    HTMLFormElement.prototype.submit = function (this: HTMLFormElement): void {
      self._recordProgrammaticSubmit(this);
      return originalSubmit.apply(this, arguments as unknown as []);
    };
  }

  _recordProgrammaticSubmit(_form: HTMLFormElement): void {
    const now = performance.now();
    this.submitData = {
      method: 'programmatic', // form.submit() called directly
      time: now,
      timeSincePageLoad: now - this.pageLoadTime,
      timeSinceFirstInteraction: this.firstInteractionTime ? now - this.firstInteractionTime : null,
      timeSinceLastInteraction: this.lastInteractionTime ? now - this.lastInteractionTime : null,
      eventsBeforeSubmit: this.totalEvents,
      hadTriggerEvent: false
    };
  }

  _recordSubmit(_e: SubmitEvent): void {
    const now = performance.now();

    // Check what triggered the submit
    const lastEvents = this.eventLog.slice(-5);
    const recentKeydown = lastEvents.find((ev) => ev.type === 'keydown' && now - ev.time < 100);
    const recentMousedown = lastEvents.find((ev) => ev.type === 'mousedown' && now - ev.time < 100);

    let method = 'unknown';
    if (recentKeydown) {
      method = 'keyboard'; // Enter key or similar
    } else if (recentMousedown) {
      method = 'mouse'; // Mouse click
    } else if (!this.submitData) {
      // No recent user event and not programmatic - likely programmatic click()
      method = 'programmatic_click';
    }

    // Don't overwrite if already recorded by intercepted submit()
    if (!this.submitData || this.submitData.method === 'programmatic') {
      this.submitData = {
        method,
        time: now,
        timeSincePageLoad: now - this.pageLoadTime,
        timeSinceFirstInteraction: this.firstInteractionTime ? now - this.firstInteractionTime : null,
        timeSinceLastInteraction: this.lastInteractionTime ? now - this.lastInteractionTime : null,
        eventsBeforeSubmit: this.totalEvents,
        hadTriggerEvent: method === 'keyboard' || method === 'mouse'
      };
    }
  }

  analyze(): Record<string, unknown> {
    const now = performance.now();

    // Textarea analysis (spam detection)
    const textareaAnalysis: Record<string, Record<string, unknown>> = {};
    this.textareaStats.forEach((stats, id) => {
      const intervals = stats.intervals;
      let avgInterval = 0;
      let intervalVariance = 0;

      if (intervals.length > 0) {
        avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        intervalVariance = intervals.reduce((acc, i) => acc + Math.pow(i - avgInterval, 2), 0) / intervals.length;
      }

      textareaAnalysis[id] = {
        keyCount: stats.keydowns.length,
        avgKeyInterval: avgInterval,
        keyIntervalVariance: intervalVariance,
        keydownUpRatio: stats.keyups.length > 0 ? stats.keydowns.length / stats.keyups.length : 0,
        pasteCount: stats.pasteCount,
        intervals: stats.intervals.slice(-100),
        dwellTimes: stats.dwellTimes.slice(-100),
        rollovers: stats.rollovers
      };
    });

    // Check for textareas with content but no keyboard events (DOM manipulation)
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach((ta: HTMLTextAreaElement) => {
      const id = ta.id || ta.name || 'unnamed';
      const contentLength = (ta.value || '').length;

      if (contentLength > 0) {
        if (!textareaAnalysis[id]) {
          // Textarea has content but we never saw any keyboard events - DOM manipulation!
          textareaAnalysis[id] = {
            keyCount: 0,
            avgKeyInterval: 0,
            keyIntervalVariance: 0,
            keydownUpRatio: 0,
            pasteCount: 0,
            contentLength: contentLength,
            noKeyboardEvents: true // Flag for server-side detection
          };
        } else {
          // Add content length for comparison
          textareaAnalysis[id].contentLength = contentLength;
          textareaAnalysis[id].noKeyboardEvents = textareaAnalysis[id].keyCount === 0;
        }
      }
    });

    return {
      // Timing signals
      pageLoadToFirstInteraction: this.firstInteractionTime ? this.firstInteractionTime - this.pageLoadTime : null,
      pageLoadToNow: now - this.pageLoadTime,
      totalInteractionEvents: this.totalEvents,

      // Submit analysis (credential stuffing detection)
      submit: this.submitData || {
        method: 'none',
        eventsBeforeSubmit: this.totalEvents,
        hadTriggerEvent: false
      },

      // Textarea analysis (spam detection)
      textareaKeyboard: Object.keys(textareaAnalysis).length > 0 ? textareaAnalysis : null
    };
  }

  // Track paste events on textareas
  recordPaste(e: ClipboardEvent): void {
    const target = e.target as (HTMLTextAreaElement & Element) | null;
    if (target?.tagName !== 'TEXTAREA') return;

    const textareaId = target.id || target.name || 'unnamed';
    if (this.textareaStats.has(textareaId)) {
      (this.textareaStats.get(textareaId) as TextareaStats).pasteCount++;
    }
  }
}

// Global form analyzer instance - initialize immediately to capture all events
let globalFormAnalyzer: FormAnalyzer | null = null;
export function getFormAnalyzer(): FormAnalyzer {
  if (!globalFormAnalyzer) {
    globalFormAnalyzer = new FormAnalyzer();
    // Also track paste events
    document.addEventListener('paste', (e: ClipboardEvent) => (globalFormAnalyzer as FormAnalyzer).recordPaste(e), { passive: true });
  }
  return globalFormAnalyzer;
}

// Initialize immediately when script loads
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => getFormAnalyzer());
  } else {
    getFormAnalyzer();
  }
}
