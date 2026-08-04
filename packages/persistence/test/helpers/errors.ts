/**
 * Capture the error a thunk threw, OUTSIDE its own catch.
 *
 * The shape this replaces asserts on the test's own guard rather than on the
 * code under test:
 *
 * ```ts
 * try {
 *   open(store);
 *   throw new Error('expected open to throw'); // caught by its own catch
 * } catch (err) {
 *   expect(primaryCode(err)).toBe(SQLITE_READONLY); // asserts on THAT error
 * }
 * ```
 *
 * A function that stops throwing entirely still satisfies it. Here a
 * never-thrown error arrives as `undefined`, so `toBeDefined()` — or a
 * `primaryCode()` comparison, which yields `undefined` for a non-error — is
 * what catches it. Assert what the error SAYS before asserting what it omits:
 * naming the expected refusal is the positive control, without which a case
 * proves only that *some* error was raised, not that the guarded branch was the
 * one reached.
 *
 * The plugin package carries its own copy in `test/helpers/no-echo.ts`; a
 * package wall blocks the import, not the pattern.
 */
export function errorFrom(fn: () => unknown): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}
