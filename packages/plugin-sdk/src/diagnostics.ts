/** Receives one diagnostic line, without its trailing newline. */
export type DiagnosticSink = (line: string) => void;

/** The sink used when none is given: the line and a newline, on stderr. */
export function writeDiagnosticToStderr(line: string): void {
  process.stderr.write(`${line}\n`);
}

/**
 * Where a diagnostic line goes: to `sink` when one is given, and to stderr
 * otherwise. A throw from `sink`, or the rejection of a promise it returns, is
 * dropped along with its line, so a sink can never change the outcome of the
 * scan that reported to it.
 */
export function diagnosticWriter(sink: DiagnosticSink | undefined): DiagnosticSink {
  if (sink === undefined) return writeDiagnosticToStderr;
  return (line) => {
    try {
      // The type lets any thenable stand in for a sink's return, a promise from
      // another realm included, which `instanceof Promise` would not recognise.
      const call: (line: string) => unknown = sink;
      const returned = call(line);
      if (returned !== undefined) Promise.resolve(returned).catch(() => undefined);
    } catch {
      // Dropped: the line is lost, and the caller's scan goes on unchanged.
    }
  };
}
