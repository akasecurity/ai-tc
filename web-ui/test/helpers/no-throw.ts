import { expect } from 'vitest';

/**
 * Await a Server Action and fail if it REJECTED rather than returned.
 *
 * A Server Action's contract is that a refusal comes back as a value the caller
 * can render. A rejected promise is not a refusal — Next turns it into a
 * framework error page, so the user loses the dialog and the guidance in it.
 * That failure mode is invisible to an ordinary `await`: the rejection surfaces
 * as an unrelated test error naming a `TypeError` deep in the action, rather
 * than as the property that was actually broken.
 *
 * So the rejection is captured and asserted on directly, and the resolved value
 * is handed back for the caller's own assertions.
 *
 * Shared rather than inlined per suite because the capture is easy to get
 * subtly wrong — a plain `try`/`catch` around the await asserts on the test's
 * own guard error instead (the same trap `expectNoEchoOf` documents), and two
 * copies of the idiom drift apart the first time one is fixed.
 */
export async function expectNoRejection<T>(call: () => Promise<T>): Promise<T> {
  const outcome = await call().then(
    (value) => ({ rejected: false as const, value }),
    (err: unknown) => ({ rejected: true as const, err: err as Error }),
  );
  // Named rather than a bare `toBe(false)`: the message is the whole point when
  // this fires, and the error it carries is what identifies the unguarded field.
  expect(outcome.rejected ? `rejected with ${String(outcome.err)}` : 'returned').toBe('returned');
  // The assertion above throws on the rejected branch, so this is the value.
  return (outcome as { rejected: false; value: T }).value;
}
