/**
 * Captures what an in-process handler writes to stderr, as the chunks it wrote.
 *
 * Two reads, for two different questions:
 *
 *  - `filtered()` drops node's own runtime warnings, so an emptiness or
 *    `toMatch` assertion is about what the hook and the SDK wrote rather than
 *    about an `ExperimentalWarning` the runtime printed on its own.
 *  - `raw()` is every byte, unfiltered. A raw-value absence check reads THIS:
 *    the filter works per chunk, so a chunk that opens like a node warning and
 *    goes on to carry a leaked run would be dropped from `filtered()` and pass
 *    the check it exists to fail.
 *
 * The spy is undone by the suite's own `vi.restoreAllMocks()`.
 */
import { vi } from 'vitest';

/** `(node:1234) ExperimentalWarning: …` and the `--trace-warnings` hint after it. */
export const NODE_WARNING = /^\(node:\d+\) |^--trace-warnings/u;

export interface StderrCapture {
  /** Everything written except node's own runtime warnings. */
  filtered(): string;
  /** Everything written, unfiltered. */
  raw(): string;
  /** Forget what has been written so far. */
  reset(): void;
}

/** Spy on `process.stderr.write`, recording each chunk instead of printing it. */
export function captureStderr(): StderrCapture {
  let chunks: string[] = [];
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    chunks.push(String(chunk));
    return true;
  });
  return {
    filtered: () => chunks.filter((chunk) => !NODE_WARNING.test(chunk)).join(''),
    raw: () => chunks.join(''),
    reset: () => {
      chunks = [];
    },
  };
}
