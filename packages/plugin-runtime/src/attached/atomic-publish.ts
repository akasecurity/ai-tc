import { rename } from 'node:fs/promises';

/**
 * Move a completed temp file onto its final name, retrying the refusals Windows
 * raises for a rename that POSIX performs silently.
 *
 * `rename(2)` on POSIX replaces the destination atomically no matter who has it
 * open, so the publish-by-rename pattern this package uses everywhere needs
 * nothing else there. Windows is different in two ways that both surface as
 * EPERM, and both are transient:
 *
 *   - the destination is open by another handle that did not ask for
 *     FILE_SHARE_DELETE — a concurrent hook READING the cache is enough;
 *   - two publishes race for the same destination and one is denied mid-flight.
 *
 * Neither means the write is wrong, and neither is a state the caller can do
 * anything useful with — the bytes are already complete in the temp file, and
 * the only thing left is to land them. A bounded retry is the accepted remedy
 * and keeps the guarantee that matters: each individual rename is still atomic,
 * so no reader ever sees a torn file. What changes is only that a loser waits
 * instead of failing.
 *
 * WHY IT MATTERS BEYOND A RED TEST: this is the policy cache. A publish that
 * throws makes `runPolicySync` record a failure, and the organization's
 * raise-only floor stays whatever it last was — so on Windows two overlapping
 * syncs could leave a machine enforcing a stale policy, intermittently, with the
 * cause showing up only as a sync outcome. It went unseen because the Windows
 * leg could not get past its install step to run these suites at all.
 *
 * The retry is deliberately SHORT and bounded. A destination held open
 * indefinitely is not a race, and turning that into a long stall would put this
 * on the wrong side of the fail-open rule — the caller is better served by an
 * error it can record than by a hook that waits.
 *
 * It retries in two phases, because the two refusals last very different
 * lengths of time. Measured on the Windows CI runner: a rename refused by
 * another rename to the same destination clears as soon as that rename lands,
 * well under a millisecond, and back-to-back renames are never refused at all —
 * but `setTimeout(1)` there waits ~14ms, a whole scheduler tick. Sleeping
 * between attempts woke every refused writer on the same tick to collide again,
 * so each round landed about one of them: twelve concurrent writers lost 13 of
 * 240 publishes under a sleep-only schedule, and none when the first retries
 * yield to the event loop instead, every landing inside 4ms. The timed tail is
 * kept for the other refusal, a handle another process holds open, which an
 * immediate retry would only spin against.
 */
const RETRYABLE = new Set(['EPERM', 'EACCES', 'EBUSY']);

/**
 * Retries that yield to the event loop instead of sleeping: the racing-rename
 * phase. Sized from the same measurement, where the worst of the 240 contended
 * writers landed on its seventh attempt.
 */
const IMMEDIATE_RETRIES = 8;

/**
 * Attempts including the first: the first, eight immediate retries, then four
 * timed ones.
 *
 * The timed tail spends 100ms of backoff, not 150: `delay(n * 10)` is reached
 * for timed retries 1 through 4 only (10 + 20 + 30 + 40), because the last
 * attempt hits the budget check and rethrows without sleeping. The immediate
 * phase adds eight event-loop turns ahead of it. Nothing measures either — the
 * tests pin the attempt COUNT and that the first phase never waits on a timer,
 * and deliberately assert no elapsed time, since a wall-clock assertion on a
 * shared runner is a flake — so this comment is the only statement of the
 * budget and is worth being right.
 */
const ATTEMPTS = IMMEDIATE_RETRIES + 5;

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const yieldToLoop = (): Promise<void> =>
  new Promise((resolve) => {
    setImmediate(resolve);
  });

export async function publishByRename(
  tmp: string,
  file: string,
  // Injectable so the refusal this exists for can be driven from a platform
  // that never produces it. Without the seam the retry branch is dead code on
  // every leg that runs these tests.
  move: (from: string, to: string) => Promise<void> = rename,
): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await move(tmp, file);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // A non-transient code, or the budget is spent: the caller owns it, and
      // owns cleaning up the temp file it created.
      if (attempt >= ATTEMPTS || code === undefined || !RETRYABLE.has(code)) throw err;
      // A turn of the event loop first, for a rename that raced this one; then
      // linear rather than exponential, since the window the tail closes is a
      // handle being released, measured in milliseconds, not a backend under
      // load.
      await (attempt <= IMMEDIATE_RETRIES
        ? yieldToLoop()
        : delay((attempt - IMMEDIATE_RETRIES) * 10));
    }
  }
}
