/** Receives one diagnostic line, without its trailing newline. */
export type DiagnosticSink = (line: string) => void;

/** The sink used when none is given: the line and a newline, on stderr. */
export function writeDiagnosticToStderr(line: string): void {
  process.stderr.write(`${line}\n`);
}
