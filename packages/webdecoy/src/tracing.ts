/**
 * OpenTelemetry spans, without depending on OpenTelemetry.
 *
 * WHY INJECTED RATHER THAN IMPORTED
 *
 * An optional peer dependency was the obvious route and the wrong one. This
 * package is dependency-free and passes an edge-compatibility gate, and most of
 * the runtimes it targets — Workers, Vercel Edge — are exactly where a stray
 * transitive import hurts. A conditional `import('@opentelemetry/api')` also
 * bundles badly: the bundler either resolves it, adding weight for the majority
 * who do not use it, or fails on a module that is legitimately absent.
 *
 * So the tracer is passed in. The interface below is a structural subset of
 * OpenTelemetry's, which means `trace.getTracer('webdecoy')` satisfies it
 * directly with no adapter:
 *
 * ```ts
 * import { trace } from '@opentelemetry/api';
 * new WebDecoy({ tracer: trace.getTracer('webdecoy') });
 * ```
 *
 * An app that passes nothing gets no spans, no dependency, and no behaviour
 * change — which is the majority, and they should not pay for this.
 */

/** A span, structurally compatible with OpenTelemetry's. */
export interface Span {
  setAttribute(key: string, value: string | number | boolean): unknown;
  recordException?(error: unknown): unknown;
  setStatus?(status: { code: number; message?: string }): unknown;
  end(): unknown;
}

/** A tracer, structurally compatible with OpenTelemetry's. */
export interface Tracer {
  startSpan(name: string): Span;
}

/** OpenTelemetry's SpanStatusCode.ERROR, inlined so the enum need not be imported. */
const STATUS_ERROR = 2;

/**
 * A span that does nothing, so call sites need no null checks.
 *
 * Every `if (span)` is a branch that can be forgotten on the path that
 * mattered, and a span left unended leaks. One object costs less than the
 * discipline.
 */
const NOOP_SPAN: Span = {
  setAttribute: () => undefined,
  end: () => undefined,
};

/**
 * Start a span, or hand back a no-op.
 *
 * Never throws. A tracer is observability, and observability that can take down
 * the request path is worse than none — a misconfigured exporter must not
 * become a 500 on a customer's site.
 */
export function startSpan(tracer: Tracer | undefined, name: string): Span {
  if (!tracer) return NOOP_SPAN;
  try {
    return tracer.startSpan(name) ?? NOOP_SPAN;
  } catch {
    return NOOP_SPAN;
  }
}

/** Set an attribute, swallowing anything the tracer throws. */
export function setAttribute(span: Span, key: string, value: string | number | boolean): void {
  try {
    span.setAttribute(key, value);
  } catch {
    // See startSpan: instrumentation must not be able to fail a request.
  }
}

/** Record a failure on the span, if the tracer supports it. */
export function recordError(span: Span, error: unknown): void {
  try {
    span.recordException?.(error);
    span.setStatus?.({
      code: STATUS_ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
  } catch {
    // As above.
  }
}

/** End a span, swallowing anything the tracer throws. */
export function endSpan(span: Span): void {
  try {
    span.end();
  } catch {
    // As above.
  }
}
