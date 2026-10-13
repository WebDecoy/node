/** @jest-environment node */
import { createClearanceFetch, readClearanceChallenge, type ClearanceRecoveryContext } from './clearance-fetch';

const origin = 'https://protected.example';
function challenged(reason = 'missing', recoverable = true, version = '1') {
  return new Response(JSON.stringify({ error: 'clearance required' }), { status: 403, headers: {
    'x-wd-clearance': 'challenged', 'x-wd-challenge': version,
    'x-wd-challenge-reason': reason, 'x-wd-challenge-recoverable': String(recoverable),
  } });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = async () => { for (let i = 0; i < 15; i++) await Promise.resolve(); };
afterEach(() => jest.useRealTimers());

test.each(['GET', 'HEAD'])('%s retries once and preserves request options', async method => {
  const first = challenged();
  const fetcher = jest.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(new Response('ok'));
  const events = jest.fn();
  const recover = jest.fn(async () => true);
  const fetch = createClearanceFetch({ origin, recover, fetch: fetcher, onEvent: events });
  const result = await fetch(new Request(origin + '/data', { method, credentials: 'include', headers: { authorization: 'fixture', 'x-custom': 'value' }, cache: 'no-cache', redirect: 'error' }));
  expect(await result.text()).toBe('ok');
  expect(first.bodyUsed).toBe(false);
  expect(fetcher).toHaveBeenCalledTimes(2);
  const retry = fetcher.mock.calls[1][0] as Request;
  expect([retry.method, retry.credentials, retry.cache, retry.redirect, retry.headers.get('authorization'), retry.headers.get('x-custom')]).toEqual([method, 'include', 'no-cache', 'error', 'fixture', 'value']);
  expect(recover).toHaveBeenCalledTimes(1);
  expect(events.mock.calls.map(call => call[0].type)).toEqual(['challenge-served', 'recovery-attempted', 'enforcement-outcome', 'recovery-succeeded']);
});

test('concurrent challenges coalesce and retry each read only once', async () => {
  const pending = deferred<boolean>();
  const recover = jest.fn(() => pending.promise);
  const calls: Record<string, number> = {};
  const fetcher = jest.fn(async (input: RequestInfo | URL) => {
    const request = input as Request;
    calls[request.url] = (calls[request.url] ?? 0) + 1;
    return calls[request.url] === 1 ? challenged() : new Response('ok');
  });
  const fetch = createClearanceFetch({ origin, recover, fetch: fetcher });
  const requests = [fetch(origin + '/one'), fetch(origin + '/two')];
  await flush();
  expect(recover).toHaveBeenCalledTimes(1);
  pending.resolve(true);
  expect((await Promise.all(requests)).map(response => response.status)).toEqual([200, 200]);
  expect(Object.values(calls)).toEqual([2, 2]);
});

test.each(['POST', 'PATCH', 'PUT', 'DELETE'])('%s sends original body once without recovery', async method => {
  const response = challenged();
  const fetcher = jest.fn(async (_input: RequestInfo | URL) => response);
  const recover = jest.fn(async () => true);
  const fetch = createClearanceFetch({ origin, recover, fetch: fetcher });
  const request = new Request(origin + '/mutation', { method, body: 'action=once' });
  expect(await fetch(request)).toBe(response);
  expect(fetcher.mock.calls[0][0]).toBe(request);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(recover).not.toHaveBeenCalled();
  expect(request.bodyUsed).toBe(false);
});

test.each([
  new Response('origin forbidden', { status: 403 }), challenged('revoked'), challenged('crawler-refused'),
  challenged('agent-impersonation'), challenged('denied'), challenged('missing', false),
  challenged('missing', true, '2'), challenged('unknown'),
])('ordinary, policy and unsupported responses never recover (%#)', async response => {
  const recover = jest.fn(async () => true);
  const fetcher = jest.fn(async () => response);
  expect(await createClearanceFetch({ origin, recover, fetch: fetcher })(origin + '/data')).toBe(response);
  expect(recover).not.toHaveBeenCalled();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

test('a second challenge is returned intact without a recovery loop', async () => {
  const second = challenged('insufficient-trust');
  const fetcher = jest.fn().mockResolvedValueOnce(challenged()).mockResolvedValueOnce(second);
  const recover = jest.fn(async () => true);
  expect(await createClearanceFetch({ origin, recover, fetch: fetcher })(origin + '/data')).toBe(second);
  expect(await second.text()).toContain('clearance required');
  expect(recover).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledTimes(2);
});

test('stronger-grade recovery receives its reason, and refusal/rejection leaves the response readable', async () => {
  for (const outcome of [false, new Error('mint denied')]) {
    const response = challenged('insufficient-trust');
    const recover = jest.fn(async (_context: ClearanceRecoveryContext) => { if (outcome instanceof Error) throw outcome; return outcome; });
    const fetcher = jest.fn(async () => response);
    expect(await createClearanceFetch({ origin, recover, fetch: fetcher })(origin + '/data')).toBe(response);
    expect(recover.mock.calls[0][0].challenge.reason).toBe('insufficient-trust');
    expect(response.bodyUsed).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(1);
  }
});

test('timeout aborts a hung resolver, returns the original response and prevents overlapping ignored cancellation', async () => {
  jest.useFakeTimers();
  const response = challenged();
  const recover = jest.fn((_context: { signal: AbortSignal }) => new Promise<boolean>(() => {}));
  const fetch = createClearanceFetch({ origin, timeoutMs: 100, recover, fetch: jest.fn(async () => response) });
  const result = fetch(origin + '/data');
  await flush();
  await jest.advanceTimersByTimeAsync(100);
  expect(await result).toBe(response);
  expect(recover.mock.calls[0][0].signal.aborted).toBe(true);
  expect(await fetch(origin + '/another')).toBe(response);
  expect(recover).toHaveBeenCalledTimes(1);
  expect(jest.getTimerCount()).toBe(0);
});

test('one cancelled waiter cannot cancel another; cancelling all stops the shared resolver', async () => {
  const pending = deferred<boolean>();
  const recover = jest.fn((_context: { signal: AbortSignal }) => pending.promise);
  const counts: Record<string, number> = {};
  const fetcher = jest.fn(async (input: RequestInfo | URL) => {
    const request = input as Request;
    counts[request.url] = (counts[request.url] ?? 0) + 1;
    return counts[request.url] === 1 ? challenged() : new Response('ok');
  });
  const fetch = createClearanceFetch({ origin, recover, fetch: fetcher });
  const controller = new AbortController();
  const first = fetch(origin + '/one', { signal: controller.signal });
  const rejection = expect(first).rejects.toMatchObject({ name: 'AbortError' });
  const second = fetch(origin + '/two');
  await flush();
  controller.abort();
  await rejection;
  expect(recover.mock.calls[0][0].signal.aborted).toBe(false);
  pending.resolve(true);
  expect((await second).status).toBe(200);

  const onlyController = new AbortController();
  const onlyRecover = jest.fn((_context: { signal: AbortSignal }) => new Promise<boolean>(() => {}));
  const only = createClearanceFetch({ origin, recover: onlyRecover, fetch: jest.fn(async () => challenged()) })(origin, { signal: onlyController.signal });
  const onlyRejection = expect(only).rejects.toMatchObject({ name: 'AbortError' });
  await flush();
  onlyController.abort();
  await onlyRejection;
  expect(onlyRecover.mock.calls[0][0].signal.aborted).toBe(true);
});

test('the retry shares the deadline, and network errors keep fetch rejection semantics', async () => {
  jest.useFakeTimers();
  const original = challenged();
  const fetcher = jest.fn().mockResolvedValueOnce(original).mockImplementationOnce((_request: Request) => new Promise<Response>(() => {}));
  const result = createClearanceFetch({ origin, timeoutMs: 100, recover: async () => true, fetch: fetcher })(origin);
  await flush();
  await jest.advanceTimersByTimeAsync(100);
  expect(await result).toBe(original);
  expect(fetcher.mock.calls[1][0].signal.aborted).toBe(true);
  const error = new TypeError('offline');
  await expect(createClearanceFetch({ origin, recover: async () => true, fetch: jest.fn().mockRejectedValue(error) })(origin)).rejects.toBe(error);
});

test('different origins, omitted credentials and redirected responses cannot start recovery', async () => {
  for (const [url, init, response] of [
    ['https://other.example/data', {}, challenged()],
    [origin + '/data', { credentials: 'omit' }, challenged()],
    [origin + '/data', {}, Object.defineProperty(challenged(), 'redirected', { value: true })],
  ] as [string, RequestInit, Response][]) {
    const recover = jest.fn(async () => true);
    expect(await createClearanceFetch({ origin, recover, fetch: jest.fn(async () => response) })(url, init)).toBe(response);
    expect(recover).not.toHaveBeenCalled();
  }
});

test('observation errors cannot change recovery and policy flags cannot override refusals', async () => {
  expect(readClearanceChallenge(challenged('revoked', true))?.recoverable).toBe(false);
  const fetcher = jest.fn().mockResolvedValueOnce(challenged()).mockResolvedValueOnce(new Response('ok'));
  expect((await createClearanceFetch({ origin, recover: async () => true, fetch: fetcher, onEvent: () => { throw new Error('observer'); } })(origin)).status).toBe(200);
});

test('caller cancellation remains attached to the retry response body after headers return', async () => {
  const controller = new AbortController();
  const fetcher = jest.fn().mockResolvedValueOnce(challenged()).mockResolvedValueOnce(new Response('ok'));
  await createClearanceFetch({ origin, recover: async () => true, fetch: fetcher })(origin, { signal: controller.signal });
  const retry = fetcher.mock.calls[1][0] as Request;
  expect(retry.signal.aborted).toBe(false);
  controller.abort();
  expect(retry.signal.aborted).toBe(true);
});

test('offline and cross-origin credential boundaries return the challenge without minting', async () => {
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const locationDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'location');
  try {
    const recover = jest.fn(async () => true);
    const response = challenged();
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { onLine: false } });
    const fetch = createClearanceFetch({ origin, recover, fetch: jest.fn(async () => response) });
    expect(await fetch(origin)).toBe(response);
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { onLine: true } });
    Object.defineProperty(globalThis, 'location', { configurable: true, value: { origin: 'https://frontend.example' } });
    expect(await fetch(origin)).toBe(response);
    expect(recover).not.toHaveBeenCalled();
  } finally {
    if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor); else delete (globalThis as any).navigator;
    if (locationDescriptor) Object.defineProperty(globalThis, 'location', locationDescriptor); else delete (globalThis as any).location;
  }
});
