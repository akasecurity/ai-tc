import { expect } from 'vitest';

/**
 * The shortest run of a raw value whose appearance is still a disclosure.
 *
 * A plain `not.toContain(value)` catches a WHOLE-value echo only — it stays
 * green if a branch ever interpolates a truncated one, and "help the user spot
 * the problem" is exactly the well-meaning change that would do it. Eight
 * characters of a base64 vault key is six raw key bytes, which is a disclosure
 * on its own and a decisive correlator against a key seen elsewhere.
 */
export const ECHO_RUN = 8;

/**
 * Assert `haystack` carries no run of `value` at all, not merely not all of it.
 *
 * Point this at a value that must not appear AT ALL — the vault key material in
 * a thrown error, or on any surface that must never carry it. Two limits decide
 * where it belongs, and each is pinned by this file's own suite:
 *
 * 1. **It proves nothing over bytes that came back empty.** Every `not.toContain`
 *    passes on `''`, and the `toBeDefined()` guard below does not catch that —
 *    it catches an `undefined` message, which is the shape a never-thrown error
 *    arrives in. Where a path produces nothing at all, assert THAT rather than
 *    searching empty bytes; where it produces something, assert a positive
 *    control on the same bytes first.
 * 2. **It is for a raw value, not a deliberately revealed fragment.** At-rest
 *    and key-shape assertions stay whole-value, because what is stored on
 *    purpose is not what this guards.
 *
 * Shared by this package's suites because they sit in one package. Across a
 * package wall it cannot be imported, so `cli/test/helpers/no-echo.ts`, the
 * three `plugins/*\/test/helpers/no-echo.ts`, `web-ui/test/helpers/no-echo.ts`
 * and `packages/setup-wizard/test/helpers/no-echo.ts` are peers of this file —
 * each a copy that takes the `toBeDefined()` guard and a `no-echo.test.ts` with
 * it, or the run length can be widened back with nothing going red.
 *
 * The peers additionally pin `maskMatch`'s preview against this window. There
 * is no counterpart here on purpose: this package has no masking surface, and
 * `@akasecurity/detections` — which owns `maskMatch` — depends on this package,
 * so reaching for it would make a dependency cycle out of a test fixture.
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
