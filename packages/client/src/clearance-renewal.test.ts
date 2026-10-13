/** @jest-environment jsdom */
import { startClearance, _resetClearanceForTests } from './clearance';
import { EnvironmentalCollector } from './collectors/environment';
import { watchInteraction } from './clearance-behavior';
jest.mock('./sha256', () => ({ sha256: jest.fn(async () => 'test-fingerprint') }));
jest.mock('./collectors/environment', () => ({ EnvironmentalCollector: jest.fn().mockImplementation(() => ({
  _getCanvasHash: () => null, _getWebGLInfo: () => null,
})) }));
jest.mock('./clearance-behavior', () => ({ watchInteraction: jest.fn() }));
const opts = { siteKey: 'test-site', behavior: false };
let cookie = '';
let fetchMock: jest.Mock;
const token = (ttl = 1800) => btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + ttl })) + '.fixture-signature';
const response = (ttl = 1800) => ({ ok: true, json: async () => ({ granted: true, token: token(ttl), expires_in: ttl }) });
const advance = async (ms: number) => { await jest.advanceTimersByTimeAsync(ms); };
beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-12T00:00:00Z'));
  cookie = '';
  Object.defineProperty(document, 'cookie', { configurable: true, get: () => cookie, set: value => { cookie = value.split(';')[0]; } });
  fetchMock = jest.fn(async () => response());
  globalThis.fetch = fetchMock;
  jest.clearAllMocks();
});
afterEach(() => { _resetClearanceForTests(); jest.useRealTimers(); });
test('active clearance renews through two lifetimes and reuses collected fingerprint', async () => {
  startClearance(opts);
  await advance(1200);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await advance(3_600_000);
  expect(fetchMock).toHaveBeenCalledTimes(3);
  expect(EnvironmentalCollector).toHaveBeenCalledTimes(1);
  expect(jest.getTimerCount()).toBe(1);
});
test('startup with fresh cookie schedules renewal without minting on every start', async () => {
  cookie = 'wd_clearance=' + token();
  startClearance(opts); startClearance(opts); startClearance(opts);
  await advance(1200);
  expect(fetchMock).not.toHaveBeenCalled();
  expect(jest.getTimerCount()).toBe(1);
  await advance(1_680_000);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});
test('an existing cookie with unknown expiry has bounded renewal', async () => {
  cookie = 'wd_clearance=legacy-cookie';
  startClearance(opts);
  await advance(1200);
  expect(fetchMock).not.toHaveBeenCalled();
  await advance(120_000);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});
test('network failures back off and visibility events cannot bypass the delay', async () => {
  fetchMock.mockRejectedValue(new Error('offline'));
  startClearance(opts);
  await advance(1200);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  for (let i = 0; i < 5; i++) document.dispatchEvent(new Event('visibilitychange'));
  await advance(59_999);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await advance(1);
  expect(fetchMock).toHaveBeenCalledTimes(2);
  await advance(120_000);
  expect(fetchMock).toHaveBeenCalledTimes(3);
  expect(jest.getTimerCount()).toBe(1);
});
test('a refused renewal is terminal and cannot replace clearance', async () => {
  fetchMock.mockResolvedValue({ ok: true, json: async () => ({ granted: false }) });
  startClearance(opts);
  await advance(1200);
  await advance(3_600_000);
  document.dispatchEvent(new Event('visibilitychange'));
  startClearance(opts);
  await advance(1200);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(cookie).toBe('');
  expect(jest.getTimerCount()).toBe(0);
});
test('short server TTLs do not create a rapid renewal loop', async () => {
  fetchMock.mockImplementation(async () => response(60));
  startClearance(opts);
  await advance(1200);
  await advance(39_999);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await advance(1);
  expect(fetchMock).toHaveBeenCalledTimes(2);
});
test('a cookie renewed by another tab postpones local minting', async () => {
  cookie = 'wd_clearance=' + token();
  startClearance(opts);
  await advance(1200);
  await advance(1_600_000);
  cookie = 'wd_clearance=' + token();
  await advance(80_000);
  expect(fetchMock).not.toHaveBeenCalled();
});
test('a hung mint is aborted and retries with bounded delay', async () => {
  fetchMock.mockImplementation((_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('aborted')));
  }));
  startClearance(opts);
  await advance(1200);
  await advance(10_000);
  expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
  expect(jest.getTimerCount()).toBe(1);
  await advance(60_000);
  expect(fetchMock).toHaveBeenCalledTimes(2);
});
test('repeated startup coalesces an in-flight mint', async () => {
  let finish!: (value: ReturnType<typeof response>) => void;
  fetchMock.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  startClearance(opts); startClearance(opts);
  await advance(1200);
  document.dispatchEvent(new Event('visibilitychange'));
  startClearance(opts);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  finish(response());
  await advance(0);
  expect(jest.getTimerCount()).toBe(1);
});
test('behavioral upgrade shares the lifecycle and keeps accepted evidence on renewal', async () => {
  startClearance({ ...opts, behavior: true });
  await advance(1200);
  const behavior = { samples: 30, duration_ms: 2000 };
  (watchInteraction as jest.Mock).mock.calls[0][0](behavior);
  await advance(0);
  expect(fetchMock).toHaveBeenCalledTimes(2);
  await advance(1_680_000);
  expect(fetchMock).toHaveBeenCalledTimes(3);
  expect(JSON.parse(fetchMock.mock.calls[2][1].body).behavior).toEqual(behavior);
  expect(EnvironmentalCollector).toHaveBeenCalledTimes(1);
  expect(jest.getTimerCount()).toBe(1);
});
test('native idle scheduling is bound to the window and has a deadline', async () => {
  const ric = jest.fn(function(this: Window, callback: () => void, options: { timeout: number }) {
    expect(this).toBe(window);
    expect(options.timeout).toBe(1200);
    callback();
  });
  Object.defineProperty(window, 'requestIdleCallback', { configurable: true, value: ric });
  try {
    startClearance(opts);
    await advance(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  } finally { delete (window as unknown as { requestIdleCallback?: unknown }).requestIdleCallback; }
});
