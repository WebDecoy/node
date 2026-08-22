import { WebDecoy } from './sdk';
import { tripwire, rateLimit } from './rules';
import type { Span, Tracer } from './tracing';
import type { RequestMetadata } from './types';

const req = (over: Partial<RequestMetadata> = {}): RequestMetadata => ({
  method: 'GET',
  path: '/',
  ip: '203.0.113.9',
  headers: {},
  timestamp: Date.now(),
  ...over,
});

interface Recorded {
  name: string;
  attributes: Record<string, unknown>;
  ended: boolean;
  errors: unknown[];
}

function recordingTracer() {
  const spans: Recorded[] = [];
  const tracer: Tracer = {
    startSpan(name: string): Span {
      const rec: Recorded = { name, attributes: {}, ended: false, errors: [] };
      spans.push(rec);
      return {
        setAttribute: (k, v) => {
          rec.attributes[k] = v;
        },
        recordException: (e) => rec.errors.push(e),
        setStatus: () => undefined,
        end: () => {
          rec.ended = true;
        },
      };
    },
  };
  return { tracer, spans };
}

describe('tracing', () => {
  it('emits a span for protect() and one for rule evaluation', async () => {
    const { tracer, spans } = recordingTracer();
    const wd = new WebDecoy({ tracer, rules: [tripwire()] });

    await wd.protect(req({ path: '/.env' }));

    expect(spans.map((s) => s.name).sort()).toEqual(['webdecoy.protect', 'webdecoy.rules']);
    expect(spans.every((s) => s.ended)).toBe(true);
  });

  it('records what an operator actually asks a trace', async () => {
    const { tracer, spans } = recordingTracer();
    const wd = new WebDecoy({ tracer, rules: [tripwire()] });

    const decision = await wd.protect(req({ path: '/.env' }));
    const protectSpan = spans.find((s) => s.name === 'webdecoy.protect')!;

    // The id is what joins this span to the dashboard row.
    expect(protectSpan.attributes['webdecoy.decision.id']).toBe(decision.id);
    expect(protectSpan.attributes['webdecoy.decision.conclusion']).toBe('DENY');
    expect(protectSpan.attributes['webdecoy.decision.allowed']).toBe(false);
    expect(protectSpan.attributes['webdecoy.decision.rule']).toBe('tripwire');
    // Settled locally: no round trip to ingest.
    expect(protectSpan.attributes['webdecoy.remote']).toBe(false);
  });

  it('names the deciding rule on the rules span', async () => {
    const { tracer, spans } = recordingTracer();
    const wd = new WebDecoy({
      tracer,
      rules: [rateLimit({ max: 1, window: 60, action: 'DENY' })],
    });

    await wd.protect(req());
    await wd.protect(req());

    const ruleSpans = spans.filter((s) => s.name === 'webdecoy.rules');
    expect(ruleSpans[0].attributes['webdecoy.rules.action']).toBe('ALLOW');
    expect(ruleSpans[1].attributes['webdecoy.rules.action']).toBe('DENY');
    expect(ruleSpans[1].attributes['webdecoy.rules.deciding']).toBe('rate-limit:1/60s');
  });

  it('ends the span even when the decision is an error', async () => {
    // A leaked span is worse than a missing one: it holds memory and never
    // reaches the exporter, so the trace is silently incomplete.
    const { tracer, spans } = recordingTracer();
    const wd = new WebDecoy({ tracer, rules: [] });

    await wd.protect(req({ ip: '' })); // malformed — decide() fails open

    const protectSpan = spans.find((s) => s.name === 'webdecoy.protect')!;
    expect(protectSpan.ended).toBe(true);
    expect(protectSpan.attributes['webdecoy.decision.conclusion']).toBe('ERROR');
    expect(protectSpan.attributes['webdecoy.error']).toBeTruthy();
  });
});

describe('a tracer must never be able to break a request', () => {
  it('survives a tracer that throws on startSpan', async () => {
    const wd = new WebDecoy({
      tracer: {
        startSpan() {
          throw new Error('exporter misconfigured');
        },
      },
      rules: [tripwire()],
    });

    // Observability that can take down the request path is worse than none.
    const decision = await wd.protect(req({ path: '/.env' }));
    expect(decision.conclusion).toBe('DENY');
  });

  it('survives a tracer that throws on every method', async () => {
    const hostile: Tracer = {
      startSpan: () =>
        ({
          setAttribute() {
            throw new Error('nope');
          },
          end() {
            throw new Error('nope');
          },
        }) as unknown as Span,
    };
    const wd = new WebDecoy({ tracer: hostile, rules: [tripwire()] });

    const decision = await wd.protect(req({ path: '/.env' }));
    expect(decision.conclusion).toBe('DENY');
  });

  it('survives a tracer that returns nothing', async () => {
    const wd = new WebDecoy({
      tracer: { startSpan: () => undefined as unknown as Span },
      rules: [tripwire()],
    });
    expect((await wd.protect(req({ path: '/.env' }))).conclusion).toBe('DENY');
  });

  it('costs nothing when no tracer is configured', async () => {
    // The majority case. No spans, no dependency, no behaviour change.
    const wd = new WebDecoy({ rules: [tripwire()] });
    expect((await wd.protect(req({ path: '/.env' }))).conclusion).toBe('DENY');
  });
});
