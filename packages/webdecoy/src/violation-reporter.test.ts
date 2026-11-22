import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebDecoyClient } from './client';
import { WebDecoy } from './sdk';
import { tripwire } from './rules';
import type { ViolationEvent } from './rules/types';
import { ViolationReporter } from './violation-reporter';

let apiUrl: string;
let status: number;
let batches: ViolationEvent[][];
const server = createServer(async (request, response) => {
  if (request.method !== 'POST' || request.url !== '/api/v1/sdk/violations/batch') {
    response.writeHead(404).end();
    return;
  }
  request.setEncoding('utf8');
  let body = '';
  for await (const chunk of request) body += chunk;
  batches.push(JSON.parse(body).events);
  response.writeHead(status).end();
});

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  apiUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

beforeEach(() => {
  status = 201;
  batches = [];
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeIdleConnections();
  });
});

test('drains a locally decided violation and exposes the ingest acknowledgment', async () => {
  const sdk = new WebDecoy({
    apiKey: 'sk_test_delivery_fixture',
    apiUrl,
    countAIReferrals: false,
    rules: [tripwire({ paths: ['/fixture-path'], includeDefaults: false })],
  });

  try {
    const decision = await sdk.protect({
      ip: '192.0.2.5', path: '/fixture-path', method: 'GET', headers: {}, timestamp: Date.now(),
    });
    expect(decision.deniedBy('tripwire')).toBe(true);
    expect(sdk.getViolationDeliveryStats()).toMatchObject({ bufferedEvents: 1, acknowledgedEvents: 0 });
  } finally {
    await sdk.destroy();
  }

  expect(batches).toHaveLength(1);
  expect(batches[0]).toEqual([expect.objectContaining({ rule: 'tripwire', action: 'DENY', path: '/fixture-path' })]);
  expect(sdk.getViolationDeliveryStats()).toEqual({
    acknowledgedEvents: 1,
    failedBatches: 0,
    droppedEvents: 0,
    bufferedEvents: 0,
  });
});

test('counts a refused batch once and keeps unattempted events for a later flush', async () => {
  const client = new WebDecoyClient({
    apiUrl, apiKey: 'sk_test_delivery_fixture', debug: false, timeout: 1_000, tlsRejectUnauthorized: true,
  });
  const reporter = new ViolationReporter(client);
  const events: ViolationEvent[] = Array.from({ length: 105 }, (_, index) => ({
    rule: 'rateLimit', action: 'THROTTLE', ip: '192.0.2.5', path: `/fixture/${index}`,
    dryRun: false, timestamp: new Date().toISOString(),
  }));

  try {
    status = 503;
    reporter.report(events);
    await Promise.all([reporter.flush(), reporter.flush()]);
    expect(batches).toEqual([events.slice(0, 100)]);
    expect(reporter.getDeliveryStats()).toEqual({
      acknowledgedEvents: 0,
      failedBatches: 1,
      droppedEvents: 100,
      bufferedEvents: 5,
    });

    status = 201;
    const clock = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 2_000);
    try {
      await reporter.flush();
    } finally {
      clock.mockRestore();
    }
    expect(batches).toEqual([events.slice(0, 100), events.slice(100)]);
    expect(reporter.getDeliveryStats()).toEqual({
      acknowledgedEvents: 5,
      failedBatches: 1,
      droppedEvents: 100,
      bufferedEvents: 0,
    });
  } finally {
    await reporter.destroy();
  }
});

test('a flush scheduled during an active send acknowledges the newly queued event', async () => {
  const client = new WebDecoyClient({
    apiUrl, apiKey: 'sk_test_delivery_fixture', debug: false, timeout: 1_000, tlsRejectUnauthorized: true,
  });
  const reporter = new ViolationReporter(client);
  let finishFirst!: (acknowledged: boolean) => void;
  const firstAck = new Promise<boolean>((resolve) => { finishFirst = resolve; });
  const send = jest.spyOn(client, 'sendViolationBatch')
    .mockReturnValueOnce(firstAck)
    .mockResolvedValue(true);
  const first: ViolationEvent = {
    rule: 'rateLimit', action: 'THROTTLE', ip: '192.0.2.5', path: '/first',
    dryRun: false, timestamp: new Date().toISOString(),
  };
  const second = { ...first, path: '/second' };

  try {
    reporter.report([first]);
    const activeFlush = reporter.flush();
    await Promise.resolve();
    expect(send).toHaveBeenCalledTimes(1);

    reporter.report([second]);
    const pendingFlush = reporter.flush();
    finishFirst(true);
    await Promise.all([activeFlush, pendingFlush]);

    expect(send.mock.calls).toEqual([[[first]], [[second]]]);
    expect(reporter.getDeliveryStats()).toMatchObject({ acknowledgedEvents: 2, bufferedEvents: 0 });
  } finally {
    finishFirst(true);
    await reporter.destroy();
  }
});
