/** Public types for the WebDecoy browser client. */

/** Assembled signal payload sent to the server for scoring. */
export interface CollectedSignals {
  behavioral: Record<string, unknown>;
  environmental: Record<string, unknown>;
  temporal: Record<string, unknown>;
  formAnalysis: Record<string, unknown>;
  meta: Record<string, unknown>;
}

/** A solved proof-of-work challenge. */
export interface PoWSolution {
  challengeId: string;
  nonce: number;
  hash: string;
  iterations: number;
  duration: number;
  difficulty: number;
  signalsHash: string | null;
  local: boolean;
}

/** Challenge as returned by `/api/pow/challenge`. */
export interface Challenge {
  challengeId: string;
  prefix: string;
  difficulty: number;
  expiresAt: number;
  nonce?: string;
  sig?: string;
  local?: boolean;
}

/** Server verify/score response. */
export interface VerifyResponse {
  success: boolean;
  score?: number;
  token?: string | null;
  recommendation?: 'allow' | 'challenge' | 'block';
  action?: string;
  message?: string | null;
  [key: string]: unknown;
}

/** Options for the checkbox widget. */
export interface WidgetOptions {
  siteKey?: string | null;
  theme?: 'light' | 'dark';
  size?: 'normal' | 'compact';
  powDifficulty?: number;
  callback?: ((token: string) => void) | null;
  errorCallback?: ((message?: string) => void) | null;
  expiredCallback?: (() => void) | null;
}

/** Options for an invisible (zero-click) session. */
export interface InvisibleOptions {
  siteKey?: string | null;
  serverUrl?: string | null;
  minCollectionTime?: number;
  autoScore?: boolean;
  scoreThreshold?: number;
  powDifficulty?: number;
}
