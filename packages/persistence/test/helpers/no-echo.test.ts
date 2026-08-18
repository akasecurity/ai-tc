import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { ECHO_RUN, expectNoEchoOf } from './no-echo.ts';

// The helper an absence assertion leans on gets its own suite, or it can be
// weakened back with nothing going red: raise ECHO_RUN past the value's length,
// or empty the loop, and every caller keeps passing while proving nothing. Each
// case here fails if that happens.
//
// The fixture is shaped like the thing this package actually has to keep out of
// an error — a base64 vault key — and is generated rather than written down, so
// no secret-shaped literal lives in this public repo.
const VALUE = randomBytes(32).toString('base64');

// Did the helper refuse this pairing? A vitest assertion failure is a throw, so
// "the assertion would have gone red" is observable without failing this test.
function refuses(haystack: string | undefined, value: string): boolean {
  try {
    expectNoEchoOf(haystack, value);
    return false;
  } catch {
    return true;
  }
}

describe('expectNoEchoOf', () => {
  it('is eight characters — widening it is a deliberate act, not a drift', () => {
    expect(ECHO_RUN).toBe(8);
    expect(VALUE.length).toBeGreaterThan(ECHO_RUN);
  });

  // The three cases below are the whole point: each output leaks a live key's
  // run, and each one passes the weaker whole-value form. The control assertion
  // in each is what proves the new form is STRONGER rather than merely also-red
  // — without it a green helper and a green predecessor look identical.
  it('refuses a prefix echo that a whole-value assertion passes', () => {
    const echoed = `keychain write failed for ${VALUE.slice(0, ECHO_RUN)}...`;
    expect(refuses(echoed, VALUE)).toBe(true);
    expect(echoed).not.toContain(VALUE); // control: the form this replaced stays green
  });

  it('refuses a tail echo that a whole-value assertion passes', () => {
    const echoed = `...${VALUE.slice(-ECHO_RUN)} was rejected`;
    expect(refuses(echoed, VALUE)).toBe(true);
    expect(echoed).not.toContain(VALUE);
  });

  it('refuses an interior run that a whole-value assertion passes', () => {
    const echoed = `near ${VALUE.slice(5, 5 + ECHO_RUN)}`;
    expect(refuses(echoed, VALUE)).toBe(true);
    expect(echoed).not.toContain(VALUE);
  });

  it('refuses a value shorter than the run, echoed whole', () => {
    // The sliding loop cannot run at all here, so the short-value fallback is
    // the only thing standing between this and a silent pass.
    const short = 'ab12cd';
    expect(short.length).toBeLessThan(ECHO_RUN);
    expect(refuses(`unknown value ${short}`, short)).toBe(true);
  });

  it('refuses an undefined haystack — a never-thrown error proves nothing', () => {
    expect(refuses(undefined, VALUE)).toBe(true);
  });

  it('accepts bytes that carry none of the value', () => {
    // The positive direction: a genuinely raw-free message must pass, or every
    // caller would be red and the helper would be useless rather than strict.
    expect(refuses('vault: keychain write failed (exit 45)', VALUE)).toBe(false);
  });

  it('passes over empty bytes — the limit that makes a positive control mandatory', () => {
    // Not a defect to fix here: `''` genuinely contains nothing. It is why a
    // caller must never point this at a capture that can come back empty
    // without also pinning that the capture is live.
    expect(refuses('', VALUE)).toBe(false);
  });
});
