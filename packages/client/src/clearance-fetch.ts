/** An explicit fetch adapter. Does not replace window.fetch or intercept XHR. */
export type ClearanceChallengeReason = 'missing' | 'invalid' | 'insufficient-trust' | 'revoked' | 'crawler-refused' | 'agent-impersonation' | 'denied';
export interface ClearanceChallenge {
  version: 1;
  reason: ClearanceChallengeReason;
  recoverable: boolean;
}
export interface ClearanceRecoveryContext {
  origin: string;
  challenge: ClearanceChallenge;
  /** Recovery UI/network work must stop when this signal aborts. */
  signal: AbortSignal;
}
export interface ClearanceFetchEvent {
  type: 'challenge-served' | 'recovery-attempted' | 'recovery-succeeded' | 'recovery-failed' | 'enforcement-outcome';
  origin: string;
  method: string;
  challenge: ClearanceChallenge;
  status?: number;
}
export interface ClearanceFetchOptions {
  /** One explicitly trusted protected origin. Use one adapter per origin/recovery flow. */
  origin: string;
  /** Earn and install clearance for this origin; true permits one safe-read retry. */
  recover(context: ClearanceRecoveryContext): Promise<boolean>;
  /** Recovery and retry deadline after the challenge; default 10s, maximum 60s. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Local observation hook; no telemetry is sent automatically. */
  onEvent?(event: ClearanceFetchEvent): void;
}

const reasons: readonly string[] = ['missing', 'invalid', 'insufficient-trust', 'revoked', 'crawler-refused', 'agent-impersonation', 'denied'];
const recoverableReasons: readonly string[] = ['missing', 'invalid', 'insufficient-trust'];

/** Header-only recognition keeps the application response body/stream untouched. */
export function readClearanceChallenge(response: Response): ClearanceChallenge | null {
  if (response.status !== 403 || response.headers.get('x-wd-clearance') !== 'challenged' || response.headers.get('x-wd-challenge') !== '1') return null;
  const reason = response.headers.get('x-wd-challenge-reason');
  const recovery = response.headers.get('x-wd-challenge-recoverable');
  if (!reason || !reasons.includes(reason) || (recovery !== 'true' && recovery !== 'false')) return null;
  // An erroneous/malicious recoverable bit can never override a policy refusal.
  return { version: 1, reason: reason as ClearanceChallengeReason, recoverable: recovery === 'true' && recoverableReasons.includes(reason) };
}

function abortError(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException('The operation was aborted', 'AbortError');
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(abortError(signal)); return; }
    const onAbort = () => reject(abortError(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

interface Recovery {
  controller: AbortController;
  promise: Promise<boolean>;
  users: number;
}

/**
 * GET/HEAD only, at most one retry per call. A callback's success is not trust:
 * the validator re-evaluates the retried request. Refusal/timeout returns the
 * original challenge response; caller cancellation and fetch errors reject.
 */
export function createClearanceFetch(options: ClearanceFetchOptions): typeof fetch {
  const parsedOrigin = new URL(options.origin);
  if (!['http:', 'https:'].includes(parsedOrigin.protocol) || parsedOrigin.username || parsedOrigin.password || parsedOrigin.pathname !== '/' || parsedOrigin.search || parsedOrigin.hash) throw new TypeError('A protected HTTP(S) origin is required');
  const origin = parsedOrigin.origin;
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new RangeError('timeoutMs must be between 1 and 60000');
  const nativeFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  let recovery: Recovery | undefined;

  function observe(type: ClearanceFetchEvent['type'], method: string, challenge: ClearanceChallenge, status?: number): void {
    try { options.onEvent?.({ type, origin, method, challenge, status }); } catch { /* Observation cannot change a request. */ }
  }

  function joinRecovery(challenge: ClearanceChallenge): Recovery {
    if (!recovery) {
      const controller = new AbortController();
      const entry: Recovery = { controller, users: 0, promise: Promise.resolve(false) };
      recovery = entry;
      const timer = setTimeout(() => controller.abort(new DOMException('Clearance recovery timed out', 'TimeoutError')), timeoutMs);
      controller.signal.addEventListener('abort', () => clearTimeout(timer), { once: true });
      // Defer invocation until the entry is installed, including synchronous callbacks.
      const actual = Promise.resolve().then(() => options.recover({ origin, challenge, signal: controller.signal }));
      entry.promise = abortable(actual, controller.signal).then(value => value === true, () => false);
      // If a resolver ignores cancellation, keep it coalesced until it settles:
      // another request must not launch a second still-running recovery UI.
      const settled = () => { clearTimeout(timer); if (recovery === entry) recovery = undefined; };
      void actual.then(settled, settled);
    }
    recovery.users++;
    return recovery;
  }

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    // Pass mutations/streams through verbatim: no cloning or body buffering.
    if (method !== 'GET' && method !== 'HEAD') {
      const response = await nativeFetch(input, init);
      const url = input instanceof Request ? input.url : String(input);
      const target = new URL(url, typeof document !== 'undefined' ? document.baseURI : undefined);
      const challenge = readClearanceChallenge(response);
      if (challenge && target.origin === origin && !response.redirected && (!response.url || new URL(response.url).origin === origin)) observe('challenge-served', method, challenge, response.status);
      return response;
    }
    const requestInput = input instanceof Request ? input : new URL(String(input), typeof document !== 'undefined' ? document.baseURI : undefined).href;
    const request = new Request(requestInput, init);
    const response = await nativeFetch(request);
    const challenge = readClearanceChallenge(response);
    if (!challenge || new URL(request.url).origin !== origin || response.redirected || (response.url && new URL(response.url).origin !== origin)) return response;
    observe('challenge-served', method, challenge, response.status);
    const pageOrigin = typeof location !== 'undefined' ? location.origin : origin;
    if (!challenge.recoverable || request.credentials === 'omit' || (pageOrigin !== origin && request.credentials !== 'include') || (typeof navigator !== 'undefined' && navigator.onLine === false) || typeof AbortSignal.any !== 'function') return response;
    if (request.signal.aborted) throw abortError(request.signal);

    const controller = new AbortController();
    let timedOut = false;
    const onAbort = () => controller.abort(abortError(request.signal));
    request.signal.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { timedOut = true; controller.abort(new DOMException('Clearance recovery timed out', 'TimeoutError')); }, timeoutMs);
    const entry = joinRecovery(challenge);
    observe('recovery-attempted', method, challenge);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      if (--entry.users === 0) entry.controller.abort();
    };
    try {
      const ready = await abortable(entry.promise, controller.signal);
      release();
      if (!ready || controller.signal.aborted) {
        observe('recovery-failed', method, challenge);
        return response;
      }
      // The caller's signal must still cancel response-body consumption after
      // we return the headers and remove the recovery listener below.
      const retrySignal = AbortSignal.any([request.signal, controller.signal]);
      const retried = await abortable(nativeFetch(new Request(request, { signal: retrySignal })), controller.signal);
      observe('enforcement-outcome', method, readClearanceChallenge(retried) ?? challenge, retried.status);
      observe(retried.ok ? 'recovery-succeeded' : 'recovery-failed', method, challenge, retried.status);
      return retried;
    } catch (error) {
      observe('recovery-failed', method, challenge);
      if (request.signal.aborted) throw abortError(request.signal);
      if (timedOut) return response;
      throw error;
    } finally {
      release();
      clearTimeout(timer);
      request.signal.removeEventListener('abort', onAbort);
    }
  };
}
