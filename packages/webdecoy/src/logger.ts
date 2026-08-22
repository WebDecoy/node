/**
 * Where the SDK's diagnostics go.
 *
 * WHY THIS EXISTS
 *
 * Observability was `debug: boolean` writing to `console.log`. In any real
 * deployment that is either off or noise: it cannot be routed into the logger
 * the app already runs, it cannot be sampled, and the lines it emits are
 * unstructured strings that a log aggregator can only match on.
 *
 * The interface is deliberately the smallest thing every logger already
 * implements — pino, winston, bunyan, `console` — so wiring one up is passing
 * it, not writing an adapter.
 */

/** A structured payload attached to a log line. */
export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

const PREFIX = '[WebDecoy]';

/**
 * The historical behaviour: `console`, and silent below `warn` unless `debug` is
 * on. Kept exactly as it was so an existing install sees no change in output.
 */
export function consoleLogger(debug: boolean): Logger {
  const emit =
    (fn: (...args: unknown[]) => void, gated: boolean) =>
    (message: string, fields?: LogFields): void => {
      if (gated && !debug) return;
      if (fields) fn(`${PREFIX} ${message}`, fields);
      else fn(`${PREFIX} ${message}`);
    };

  return {
    debug: emit(console.log, true),
    info: emit(console.log, true),
    // Warnings and errors are not debug output. A violation that failed to
    // report, or a key that was rejected, is something the operator needs to
    // see whether or not they opted into diagnostics.
    warn: emit(console.warn, false),
    error: emit(console.error, false),
  };
}

/** Discards everything. Useful in tests and in the testing utilities. */
export const silentLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/**
 * Wrap a pino-style logger, which takes `(fields, message)` — the opposite
 * order to this interface and to `console`.
 *
 * Passing a pino instance directly would type-check and then quietly mangle
 * every line: pino reads the first argument as the message and treats the second
 * as printf interpolation, so the structured fields vanish. Nobody notices until
 * they need the log. One explicit wrapper is better than argument-order
 * guesswork that is wrong for somebody.
 *
 * ```ts
 * new WebDecoy({ logger: fromPino(pino()) });
 * ```
 */
export function fromPino(pino: {
  debug(fields: LogFields, message: string): void;
  info(fields: LogFields, message: string): void;
  warn(fields: LogFields, message: string): void;
  error(fields: LogFields, message: string): void;
}): Logger {
  return {
    debug: (m, f) => pino.debug(f ?? {}, m),
    info: (m, f) => pino.info(f ?? {}, m),
    warn: (m, f) => pino.warn(f ?? {}, m),
    error: (m, f) => pino.error(f ?? {}, m),
  };
}

/** The configured logger, or the historical console behaviour. */
export function resolveLogger(provided: Logger | undefined, debug: boolean): Logger {
  return provided ?? consoleLogger(debug);
}
