import { expect } from 'vitest';

/**
 * The shortest run of a raw value whose appearance is still a disclosure.
 *
 * A plain `not.toContain(value)` catches a WHOLE-value echo only — it stays
 * green if a branch ever interpolates a truncated one, and "help the user spot
 * their typo" is exactly the well-meaning change that would do it. Eight
 * characters of a 40-character token is a real disclosure, and for the shorter
 * values other bundled rules match it is most of the secret.
 */
export const ECHO_RUN = 8;

/**
 * Assert `haystack` carries no run of `value` at all, not merely not all of it.
 *
 * Point this at a value that must not appear AT ALL — a raw secret in a Server
 * Action's error. Three limits decide where it belongs, and each one is pinned
 * by this file's own suite:
 *
 * 1. **It proves nothing over bytes that came back empty.** Every `not.toContain`
 *    passes on `''`, and the `toBeDefined()` guard below does not catch that —
 *    it catches an action returning no error at all, which is the shape a
 *    never-failed call arrives in. Where the searched bytes could be empty, pin
 *    a positive control on them first.
 * 2. **It is for a raw value, not a deliberately revealed fragment.** The
 *    at-rest and grant-shape assertions stay whole-value (`not.toContain`)
 *    because `maskMatch` keeps a fragment visible on purpose — that fragment IS
 *    the masked preview, and it is stored deliberately.
 * 3. **A masked preview only stays under the window for a GENERIC secret.**
 *    `maskMatch` reveals a generic secret's first and last character around six
 *    fixed asterisks — two characters, which cannot fill an eight-character
 *    window. Its email branch reveals the first local character plus the WHOLE
 *    DOMAIN, and a single-character local part returns the input unchanged, so
 *    an email's own preview fills the window legitimately.
 *
 * Shared by this package's suites because they sit behind one package wall.
 * Across a wall it cannot be imported, so `cli/test/helpers/no-echo.ts` and
 * `plugins/claude-code/test/helpers/no-echo.ts` carry their own — a copy takes
 * the `toBeDefined()` guard and this file's suite with it, or the run length can
 * be widened back with nothing going red.
 */
export function expectNoEchoOf(haystack: string | undefined, value: string): void {
  // Catches an action that returned no error, which would otherwise satisfy the
  // loop vacuously. It does NOT catch an empty string — see limit 1.
  expect(haystack).toBeDefined();
  const text = haystack ?? '';
  for (let i = 0; i + ECHO_RUN <= value.length; i += 1) {
    expect(text).not.toContain(value.slice(i, i + ECHO_RUN));
  }
  // Values shorter than the run length still must not appear at all.
  if (value.length < ECHO_RUN) expect(text).not.toContain(value);
}
