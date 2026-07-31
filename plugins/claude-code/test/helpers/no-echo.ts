import { expect } from 'vitest';

/**
 * The shortest run of a raw value whose appearance is still a disclosure.
 *
 * A plain `not.toContain(value)` catches a WHOLE-value echo only — it stays
 * green if a branch ever interpolates a truncated one, and "say which value
 * failed" is exactly the well-meaning change that would do it. Eight characters
 * is a substantial fraction of every value the bundled rules match, and for the
 * shorter ones it is most of the secret.
 */
export const ECHO_RUN = 8;

/**
 * Assert `haystack` carries no run of `value` at all, not merely not all of it.
 *
 * Point this at a value that must not appear AT ALL — a raw hit in an error
 * that reaches the parent command's stderr, or in a message built for the user.
 * Three limits decide where it belongs, and each one is pinned by this file's
 * own suite:
 *
 * 1. **It proves nothing over bytes that came back empty.** Every `not.toContain`
 *    passes on `''`, and the `toBeDefined()` guard below does not catch that —
 *    it catches an `undefined` message, which is the shape a never-thrown error
 *    arrives in. A builder returning `string` is never undefined, so the guard
 *    is inert there. Pin a positive control on the same bytes first.
 * 2. **A thrown-from-the-try guard defeats it.** `try { f(); throw new Error('expected
 *    f to throw') } catch (e) { … }` catches the test's OWN error and asserts
 *    against a message that never held a secret, so it passes while `f` stopped
 *    throwing entirely. Capture the error outside the catch and assert what it
 *    says before asserting what it omits.
 * 3. **It is for a raw value, not a deliberately revealed fragment.** A masked
 *    preview is built and shown on purpose, so at-rest and grant-shape
 *    assertions stay whole-value — `triage/writeback.test.ts` on `maskedValue`
 *    and `triage/surfaced-secrets.test.ts` on `maskedToken` are the two here.
 *    A generic secret's preview reveals two characters and cannot fill the
 *    window, which is what lets a surface printing one be searched at all;
 *    `cli/test/helpers/no-echo.ts` carries the rest of that boundary, including
 *    why an email preview fills the window legitimately.
 *
 * Shared by this package's suites because they sit behind one package wall.
 * Across a wall it cannot be imported, so `cli/test/helpers/no-echo.ts` and
 * `web-ui/test/helpers/no-echo.ts` are peers of this file — each a copy that
 * takes the `toBeDefined()` guard and a `no-echo.test.ts` with it, or the run
 * length can be widened back with nothing going red.
 */
export function expectNoEchoOf(haystack: string | undefined, value: string): void {
  // Catches a never-thrown error arriving as `undefined`, which would otherwise
  // satisfy the loop vacuously. It does NOT catch an empty string — see limit 1.
  expect(haystack).toBeDefined();
  const text = haystack ?? '';
  for (let i = 0; i + ECHO_RUN <= value.length; i += 1) {
    expect(text).not.toContain(value.slice(i, i + ECHO_RUN));
  }
  // Values shorter than the run length still must not appear at all.
  if (value.length < ECHO_RUN) expect(text).not.toContain(value);
}

/**
 * Run `fn` and return the error it threw, or `undefined` if it returned.
 *
 * The shape limit 2 above exists for: the caller asserts on the returned value,
 * so a function that stopped throwing yields `undefined` and every assertion
 * below it goes red — where a `throw` inside the `try` would have been caught
 * by the same `catch` and quietly asserted against instead.
 */
export function errorFrom(fn: () => unknown): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e as Error;
  }
}
