/**
 * Reads a hook's stdout the way the Copilot CLI's hooks reference says the
 * host reads it ("How stdout is parsed when progress messages are mixed in"):
 *
 *  - stdout is scanned line by line;
 *  - a line that, after trimming, is a single complete JSON object with
 *    `"type": "progress"` is consumed as a progress event and removed;
 *  - every other line is kept verbatim;
 *  - what is kept is concatenated, trimmed and parsed with one `JSON.parse`;
 *    empty or unparseable output means "no output" — default behavior.
 *
 * A model of the host, not the host. It exists so a test can assert both
 * halves of a CLI run separately: what the user is shown (the progress
 * messages) and what the host decides on (the output). A test that read stdout
 * whole could not tell a notice from a verdict.
 */
export interface CliStdout {
  /** The progress messages, in the order they were written. */
  progress: string[];
  /** What is left once they are removed, trimmed, before parsing. */
  rest: string;
  /** The parsed hook output, or undefined when `rest` is empty. */
  output: unknown;
}

function asProgress(line: string): string | undefined {
  const trimmed = line.trim();
  if (!trimmed.startsWith('{')) return undefined;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    const record = parsed as Record<string, unknown>;
    return record.type === 'progress' && typeof record.message === 'string'
      ? record.message
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Split CLI stdout into its progress messages and its output.
 *
 * THROWS when what remains is non-empty and does not parse. The host would
 * read that as no output at all, silently dropping any verdict in it, so a
 * test reaching it has found a defect rather than an answer.
 */
export function readCliStdout(stdout: string): CliStdout {
  const progress: string[] = [];
  const kept: string[] = [];
  for (const line of stdout.split('\n')) {
    const message = asProgress(line);
    if (message === undefined) kept.push(line);
    else progress.push(message);
  }
  const rest = kept.join('\n').trim();
  return { progress, rest, output: rest === '' ? undefined : (JSON.parse(rest) as unknown) };
}
