/**
 * Direct descriptor accounting, so a store handle that escapes a failed open is
 * observable where it happens rather than only as a teardown failure on Windows.
 *
 * A leaked `DatabaseSync` is an OS descriptor the caller can no longer reach.
 * Windows reports that loudly — it refuses to delete a file some handle still
 * holds — but POSIX unlinks an open file happily, so the removal-based guard is
 * silent on Linux and macOS. That leaves the regression caught only on the one
 * CI leg with the fewest packages in it. Counting descriptors closes that: the
 * leak becomes a number on every developer machine.
 *
 * ## Why the count is a total, not a per-file one
 *
 * Resolving each descriptor to its path would let the probe name the store file
 * and ignore everything else, and on Linux `/proc/self/fd/N` is a symlink that
 * answers exactly that. macOS is not: its `/dev/fd/N` entries are character
 * devices, and `readlink` on one yields nothing usable. Rather than have the
 * probe mean two different things on two platforms, it counts the whole table.
 *
 * ## Why a total count is not flaky
 *
 * Because the measured window is **synchronous**, and because it runs inside one
 * OS process. The second half is not this module's doing: this package's
 * `vitest.config.ts` sets no `pool`, so it inherits vitest 4's default,
 * `pool: 'forks'` — one process per test file, each with its own descriptor
 * table. Switch that config to `pool: 'threads'` and every worker in the process
 * shares one table, so another file's `openLocalDatabase` can land inside this
 * delta while this file's thunk runs — the window would still be synchronous and
 * the count would still be wrong.
 *
 * Within that process, a synchronous window means no timer, no socket, no `fs`
 * completion and no reporter callback can run between the two counts — the only
 * code that executes inside the window is the thunk itself. `leakedBy` refuses a
 * thunk that returns a thenable for that reason: an `await` inside would hand
 * the loop back, unrelated I/O would settle, and the delta would stop describing
 * the thunk.
 *
 * One gap survives both: Node's async `fs` calls run their actual syscall on a
 * libuv threadpool thread, not the main one, so a call already in flight when
 * the window opens can have its descriptor allocated inside the window even
 * though its JS callback cannot fire there. That is a low-probability window —
 * reporter and source-map I/O, mostly — not a zero one, which is why the
 * counting tests that use this probe assert an exact `leaked === 0` rather than
 * a looser bound: a stray tick fails loudly instead of hiding a leak.
 *
 * ## Why the probe validates itself
 *
 * A counter that always answers the same number reports "nothing leaked" for
 * every input, and an absence assertion built on it passes forever. So
 * `descriptorProbe()` proves the mechanism against a descriptor it opens itself
 * before reporting `observable: true`: the count must rise by one on an open and
 * fall back on the close. Where it does not — Windows has no `/dev/fd` at all —
 * the probe reports `observable: false` with a reason and the caller skips, the
 * way `readOnlyStore` reports a mode the platform ignored.
 */
import { closeSync, openSync, readdirSync } from 'node:fs';

/** The descriptor table, as this process can see it. */
const FD_DIR = '/dev/fd';

export interface DescriptorProbe {
  /**
   * Whether descriptor counting works here. False where the platform exposes no
   * descriptor table, or exposes one that does not track opens — a test that
   * asserts "no descriptor leaked" must skip rather than pass on a probe that
   * cannot see one.
   */
  readonly observable: boolean;
  /** Why counting is unavailable, when `observable` is false. */
  readonly reason: string | undefined;
  /** Descriptors currently open in this process. Throws when not `observable`. */
  count(): number;
  /**
   * Run `fn` and return how many descriptors it left behind — 0 when it opened
   * none, or closed everything it opened.
   *
   * `fn` must be synchronous. A thunk returning a thenable is refused rather
   * than measured, because the window would no longer be this thread's alone.
   * The parameter is `() => unknown` rather than `() => void` so that refusal
   * can read the return value: `void` would have the caller's async function
   * type-check here and then be measured as if it had finished.
   */
  leakedBy(fn: () => unknown): number;
}

function readCount(): number | undefined {
  try {
    return readdirSync(FD_DIR).length;
  } catch {
    return undefined;
  }
}

/** True for anything with a callable `then` — a promise, or a promise-alike. */
function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

/**
 * A descriptor probe for this process, self-checked at construction.
 *
 * The self-check opens `process.execPath` — the running node binary, which is
 * readable by definition on any platform that got this far — so the probe needs
 * no fixture and no temp dir of its own.
 */
export function descriptorProbe(): DescriptorProbe {
  const unusable = (reason: string): DescriptorProbe => ({
    observable: false,
    reason,
    count: (): number => {
      throw new Error(`descriptorProbe(): ${reason}`);
    },
    leakedBy: (): number => {
      throw new Error(`descriptorProbe(): ${reason}`);
    },
  });

  const base = readCount();
  if (base === undefined) {
    return unusable(`cannot read ${FD_DIR} — descriptor counting is unavailable on this platform`);
  }

  // Prove the count tracks an open before trusting it to report a leak.
  let raised: number | undefined;
  const fd = openSync(process.execPath, 'r');
  try {
    raised = readCount();
  } finally {
    closeSync(fd);
  }
  const restored = readCount();

  if (raised !== base + 1 || restored !== base) {
    return unusable(
      `${FD_DIR} does not track opens (saw ${String(base)} → ${String(raised)} → ${String(restored)} ` +
        'around one open/close) — a count that cannot see a descriptor cannot report a leak',
    );
  }

  const count = (): number => {
    const now = readCount();
    if (now === undefined) {
      throw new Error(`descriptorProbe(): ${FD_DIR} became unreadable mid-run`);
    }
    return now;
  };

  return {
    observable: true,
    reason: undefined,
    count,
    leakedBy: (fn: () => unknown): number => {
      const before = count();
      const result = fn();
      if (isThenable(result)) {
        throw new Error(
          'descriptorProbe().leakedBy(): the thunk returned a thenable. The measurement window ' +
            'has to be synchronous — an await inside it hands the loop back and unrelated I/O ' +
            'lands in the delta.',
        );
      }
      return count() - before;
    },
  };
}
