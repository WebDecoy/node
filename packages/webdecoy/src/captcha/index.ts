/**
 * Self-hosted captcha: proof-of-work + in-process detection + session tokens.
 *
 * Ported from FCaptcha. Use {@link Captcha} for the full flow, or the
 * {@link PoWManager} / {@link TokenManager} primitives directly.
 */

export { Captcha } from './service';
export type { CaptchaOptions } from './service';

export { PoWManager, InMemoryChallengeStore } from './pow';
export type { PoWManagerOptions, ChallengeStore } from './pow';

export { TokenManager, InMemoryTokenStore } from './token';
export type { TokenManagerOptions, TokenStore } from './token';

export { resolveSecret, INSECURE_DEFAULT_SECRET } from './secret';

export { createCaptchaEndpoints } from './http';
export type {
  CaptchaEndpoints,
  CaptchaEndpointsOptions,
  CaptchaRequest,
  CaptchaHttpResponse,
} from './http';

export type {
  ChallengeData,
  StoredChallenge,
  PoWSolution,
  PoWVerification,
  TokenVerification,
  VerifyInput,
  VerifyResult,
  ScoreResult,
} from './types';
