/**
 * A spawned child's stderr with Node's OWN diagnostics removed, leaving what the
 * CLI itself wrote.
 *
 * Asserting a spawned Node process writes nothing to stderr is a promise the
 * runtime does not make: an ExperimentalWarning from the loader, or any
 * deprecation notice, lands there beside whatever the CLI said. What the spawn
 * cases are about is the CLI's own output, which the bin entry prefixes with
 * `aka:`.
 *
 * A Node warning is TWO lines, and the second is the one that is easy to miss:
 *
 *     (node:12345) DeprecationWarning: some message
 *     (Use `node --trace-deprecation ...` to show where the warning was created)
 *
 * The hint line matches neither the `(node:N)` prefix nor a stack frame, so a
 * filter aimed only at those leaves it behind and `toBe('')` fails on it. It
 * comes in two spellings — `--trace-warnings` and `--trace-deprecation`,
 * whichever warning the process emitted first — and a filter covering one covers
 * the other only by accident.
 *
 * The risk runs BOTH ways, which is what decides how the patterns are written:
 *
 * - Too narrow and a case reddens on output the CLI never produced. That is
 *   loud, and it is the safe direction to err in.
 * - Too broad and the filter eats the CLI's own words. Nothing goes red — the
 *   absence assertions this feeds pass on empty bytes, and the one positive
 *   control among them is the only thing that would notice. So every pattern
 *   here is ANCHORED at the start of a line and matches a shape the CLI cannot
 *   produce.
 *
 * Trailing whitespace is tolerated at the end of each pattern because splitting
 * CRLF output on `\n` leaves a `\r` behind, which a bare `$` would not match.
 *
 * This has its own suite (`cli-stderr.test.ts`) for the reason `no-echo.ts`
 * does: broadening it leaves every CALLER green — more green, in fact, since the
 * assertions it feeds are absence checks — so a caller can never be what goes
 * red when it is weakened.
 */

/** Node's own `(node:PID)` / `(tsx:PID)` warning prefix. */
const NODE_WARNING_LINE = /^\((?:node|tsx):\d+\)/u;

/** A stack frame, or a bare continuation of a warning body. */
const STACK_OR_WARNING_LINE = /^\s*(?:at |Warning:)/u;

/**
 * The hint line Node prints under the first warning of a run. Anchored on
 * `--trace-`, which is what separates it from a CLI hint that merely opens with
 * `(Use ` — `(Use the --home flag)` is kept, this is not.
 */
const TRACE_HINT_LINE = /^\(Use `node --trace-[\w-]+ \.\.\.`.*\)\s*$/u;

export function cliStderr(stderr: string): string {
  return stderr
    .split('\n')
    .filter(
      (line) =>
        !NODE_WARNING_LINE.test(line) &&
        !STACK_OR_WARNING_LINE.test(line) &&
        !TRACE_HINT_LINE.test(line),
    )
    .join('\n')
    .trim();
}
