/**
 * @webdecoy/client — browser widget for WebDecoy captcha.
 *
 * Collects ~40 behavioral/environmental/fingerprint signals, solves a SHA-256
 * proof-of-work, and submits to a WebDecoy-protected server endpoint. Pairs with
 * the in-process detection engine in `@webdecoy/node`.
 *
 * @example
 * ```ts
 * import { WebDecoyCaptcha } from '@webdecoy/client';
 * WebDecoyCaptcha.configure({ serverUrl: 'https://api.example.com' });
 * WebDecoyCaptcha.render('captcha-box', { siteKey: 'pk_live_...' });
 * ```
 */

export { WebDecoyCaptcha } from './client';
export type { WebDecoyCaptchaAPI } from './client';

export { CaptchaWidget } from './widget';
export { InvisibleSession } from './invisible';
export { PoWManager, getPoWManager } from './pow';
export { TemporalCollector } from './temporal';
export { BehavioralCollector } from './collectors/behavioral';
export { EnvironmentalCollector } from './collectors/environment';
export { SensorCollector } from './collectors/sensor';
export { FormAnalyzer, getFormAnalyzer } from './collectors/form';
export { sha256 } from './sha256';

export type {
  CollectedSignals,
  PoWSolution,
  Challenge,
  VerifyResponse,
  WidgetOptions,
  InvisibleOptions,
} from './types';
