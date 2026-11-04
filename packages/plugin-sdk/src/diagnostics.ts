/** Receives one diagnostic line, without its trailing newline. */
export type DiagnosticSink = (line: string) => void;

/** The sink used when none is given: the line and a newline, on stderr. */
export function writeDiagnosticToStderr(line: string): void {
  process.stderr.write(`${line}\n`);
}

/**
 * Where a diagnostic line goes: to `sink` when one is given, and to stderr
 * otherwise. A throw from `sink` is dropped along with its line, so a sink can
 * never change the outcome of the scan that reported to it.
 */
export function diagnosticWriter(sink: DiagnosticSink | undefined): DiagnosticSink {
  if (sink === undefined) return writeDiagnosticToStderr;
  return (line) => {
    try {
      sink(line);
    } catch {
      // Dropped: the line is lost, and the caller's scan goes on unchanged.
    }
  };
}
