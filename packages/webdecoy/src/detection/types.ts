/**
 * Detection engine types.
 *
 * The detection engine scores a set of client-collected `Signals` against ~40
 * behavioral, environmental, and fingerprint heuristics and produces a verdict.
 * Ported from the FCaptcha scoring engine so behavior matches the self-hosted
 * server (server.js `runVerification`).
 *
 * Signals originate from an untrusted client, so every field is optional and the
 * detectors fall back to neutral defaults (mirroring the `?? default` pattern in
 * the reference implementation).
 */

/** A single triggered heuristic. */
export interface Detection {
  /** Scoring bucket this detection contributes to (see {@link Weights}). */
  category: string;
  /** Likelihood this signal indicates a bot/attack, 0..1. */
  score: number;
  /** Certainty of the score, 0..1, used to weight the per-category aggregate. */
  confidence: number;
  /** Human-readable explanation. */
  reason: string;
  /** Optional structured detail (e.g. keystroke-cadence metrics). */
  details?: Record<string, unknown>;
}

/** Per-category aggregated scores (0..1), keyed by category name. */
export type CategoryScores = Record<string, number>;

/** Final action recommendation derived from the weighted score. */
export type Recommendation = 'allow' | 'challenge' | 'block';

/** Behavioral signals: mouse, touch, keyboard, and interaction timing. */
export interface BehavioralSignals {
  totalPoints?: number;
  trajectoryLength?: number;
  approachPoints?: number;
  touchEvents?: number;
  keyEvents?: number;
  microTremorScore?: number;
  approachDirectness?: number;
  clickPrecision?: number;
  explorationRatio?: number;
  velocityVariance?: number;
  overshootCorrections?: number;
  interactionDuration?: number;
  mouseEventRate?: number;
  straightLineRatio?: number;
  directionChanges?: number;
  eventDeltaVariance?: number;
  // Mobile touch authenticity / kinematics
  touchTotalPoints?: number;
  touchForceMin?: number;
  touchForceMax?: number;
  touchForceVariance?: number;
  touchForceAllOne?: boolean;
  touchForceAllZero?: boolean;
  touchRadiusMin?: number;
  touchRadiusMax?: number;
  touchRadiusVariance?: number;
  touchUniqueIdentifiers?: number;
  touchMultiTouchSeen?: boolean;
  touchStraightLineRatio?: number;
  touchMicroTremorScore?: number;
  touchDirectionChanges?: number;
  [key: string]: unknown;
}

export interface PoWTiming {
  duration?: number;
  iterations?: number;
  [key: string]: unknown;
}

export interface TemporalSignals {
  pow?: PoWTiming;
  pageLoadToFirstInteraction?: number | null;
  [key: string]: unknown;
}

export interface EnvironmentalSignals {
  webdriver?: boolean;
  headlessIndicators?: {
    hasOuterDimensions?: boolean;
    innerEqualsOuter?: boolean;
    notificationPermission?: string;
    [key: string]: unknown;
  };
  automationFlags?: {
    plugins?: number;
    languages?: boolean;
    chrome?: boolean;
    platform?: string;
    maxTouchPoints?: number;
    hardwareConcurrency?: number;
    [key: string]: unknown;
  };
  navigator?: {
    platform?: string;
    maxTouchPoints?: number;
    [key: string]: unknown;
  };
  webglInfo?: { renderer?: string; [key: string]: unknown };
  playwright?: { detected?: boolean; signals?: string[] };
  cdp?: { detected?: boolean; signals?: string[] };
  jsExecutionTime?: { mathOps?: number; [key: string]: unknown };
  rafConsistency?: { frameTimeVariance?: number; [key: string]: unknown };
  canvasHash?: { hash?: string; error?: unknown; supported?: boolean; [key: string]: unknown };
  sensor?: {
    motionEventCount?: number;
    motionAccelVariance?: number;
    orientationEventCount?: number;
    orientationVariance?: number;
    [key: string]: unknown;
  };
  webrtcInfo?: WebRTCInfo;
  speechInfo?: SpeechInfo;
  workerConsistency?: WorkerConsistencyInfo;
  cssMediaQueries?: CSSMediaQueriesInfo;
  fontsInfo?: FontsInfo;
  permissionsInfo?: PermissionsInfo;
  domRectFingerprint?: DOMRectInfo;
  audioInfo?: AudioContextInfo;
  lieDetection?: LieDetectionInfo;
  [key: string]: unknown;
}

export interface WebRTCInfo {
  supported?: boolean;
  mediaDevices?: {
    supported?: boolean;
    audioInputs?: number;
    audioOutputs?: number;
    videoInputs?: number;
    totalDevices?: number;
  };
  hasLocalIP?: boolean;
  localIPError?: unknown;
  [key: string]: unknown;
}

export interface SpeechInfo {
  supported?: boolean;
  totalVoices?: number;
  localVoices?: number;
  [key: string]: unknown;
}

export interface WorkerConsistencyInfo {
  supported?: boolean;
  consistent?: boolean;
  mismatches?: string[];
  mismatchCount?: number;
  [key: string]: unknown;
}

export interface CSSMediaQueriesInfo {
  supported?: boolean;
  pointer?: string;
  hover?: boolean;
  [key: string]: unknown;
}

export interface FontsInfo {
  supported?: boolean;
  count?: number;
  hasSegoeUI?: boolean;
  hasSFPro?: boolean;
  hasDejaVuSans?: boolean;
  [key: string]: unknown;
}

export interface PermissionsInfo {
  supported?: boolean;
  [key: string]: unknown;
}

export interface DOMRectInfo {
  supported?: boolean;
  rectAWidth?: number;
  rectBWidth?: number;
  rangeWidth?: number;
  [key: string]: unknown;
}

/** AudioContext fingerprint. A real audio stack exposes `baseLatency` and a
 *  conventional sample rate; headless/mocked stacks omit or fake these. */
export interface AudioContextInfo {
  supported?: boolean;
  sampleRate?: number;
  state?: string;
  baseLatency?: number | null;
  [key: string]: unknown;
}

/** Native-function integrity check. `patched` lists native functions whose
 *  `toString()` no longer reports `[native code]` (or whose prototype was
 *  tampered with) — the signature of stealth automation hiding itself. A real
 *  browser never patches its own natives. */
export interface LieDetectionInfo {
  supported?: boolean;
  patched?: string[];
  patchedCount?: number;
  [key: string]: unknown;
}

/** Per-field keystroke statistics for one textarea. */
export interface TextareaKeyboardStats {
  keyCount?: number;
  pasteCount?: number;
  avgKeyInterval?: number;
  keyIntervalVariance?: number;
  keydownUpRatio?: number;
  noKeyboardEvents?: boolean;
  contentLength?: number;
  intervals?: number[];
  dwellTimes?: number[];
  rollovers?: number;
  [key: string]: unknown;
}

export interface FormSubmitInfo {
  method?: string;
  timeSincePageLoad?: number | null;
  eventsBeforeSubmit?: number;
  hadTriggerEvent?: boolean;
  [key: string]: unknown;
}

export interface FormAnalysisSignals {
  pageLoadToFirstInteraction?: number | null;
  submit?: FormSubmitInfo;
  textareaKeyboard?: Record<string, TextareaKeyboardStats>;
  [key: string]: unknown;
}

/** The full set of signals the client widget reports. */
export interface Signals {
  behavioral?: BehavioralSignals;
  temporal?: TemporalSignals;
  environmental?: EnvironmentalSignals;
  formAnalysis?: FormAnalysisSignals;
  meta?: { challengeNonce?: string; [key: string]: unknown };
  [key: string]: unknown;
}

/**
 * Outcome of proof-of-work verification, supplied by the caller (the PoW
 * subsystem lands in Phase 2). When omitted and `requirePoW` is enabled the
 * engine emits a hard-fail "No PoW solution provided" detection, matching the
 * reference server.
 */
export interface PoWOutcome {
  /** Whether a PoW solution was submitted at all. */
  provided: boolean;
  /** Whether the submitted solution verified. */
  valid?: boolean;
  /** Failure reason when `valid` is false. */
  reason?: string;
  /** Server-measured solve time in ms (un-spoofable). */
  serverElapsed?: number;
  /** Nonce bound to the verified challenge. */
  nonce?: string;
}

/** Per-request context for scoring. */
export interface DetectionContext {
  ip: string;
  siteKey: string;
  userAgent: string;
  /** Lower-cased request headers. */
  headers?: Record<string, string>;
  /** Client-supplied JA3 hash (spoofable). */
  ja3Hash?: string | null;
  /**
   * Trusted reverse-proxy header names carrying a JA4 fingerprint, matched
   * against the lower-cased `headers` keys. The value is checked against
   * `KNOWN_BOT_JA4_HASHES`, which ships empty, so it does not currently
   * change the score.
   */
  trustedJA4Headers?: string[];
  /** Proof-of-work verification outcome (supplied by the PoW subsystem). */
  pow?: PoWOutcome;
  /**
   * Additional detections to fold into scoring, produced by an outer
   * orchestrator (e.g. the signals-tampering check in the Captcha service).
   */
  extraDetections?: Detection[];
}

/** Final verdict returned by {@link DetectionEngine.score}. */
export interface Verdict {
  /** True when the weighted score is below the success threshold (< 0.5). */
  success: boolean;
  /** Weighted final score, 0..1. */
  score: number;
  /** Recommended action. */
  recommendation: Recommendation;
  /** Per-category aggregated scores. */
  categoryScores: CategoryScores;
  /** Every triggered detection. */
  detections: Detection[];
  /** Unix seconds at evaluation time. */
  timestamp: number;
}
