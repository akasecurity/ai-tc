import { maskMatch } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { ECHO_RUN, errorFrom, expectNoEchoOf } from './no-echo.ts';

// The helper an absence assertion leans on gets its own suite, or it can be
// weakened back with nothing going red: raise ECHO_RUN past the value's length,
// or empty the loop, and every caller keeps passing while proving nothing. Each
// case here fails if that happens.
//
// Composed at runtime so the repo's own secret scan never flags this file.
const VALUE = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

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
    // The callers' comments cite this number as what makes a run-by-run check
    // stronger than the whole-value form. Move it and that has to be re-derived.
    expect(ECHO_RUN).toBe(8);
    expect(VALUE.length).toBeGreaterThan(ECHO_RUN);
  });

  // The three cases below are the whole point: each output leaks a live
  // credential's run, and each one passes the weaker whole-value form. The
  // control assertion in each is what proves the new form is STRONGER rather
  // than merely also-red — without it a green helper and a green predecessor
  // look identical.
  it('refuses a prefix echo that a whole-value assertion passes', () => {
    const echoed = `judge failed near ${VALUE.slice(0, ECHO_RUN)}...`;
    expect(refuses(echoed, VALUE)).toBe(true);
    expect(echoed).not.toContain(VALUE); // control: the form this replaced stays green
  });

  it('refuses a tail echo that a whole-value assertion passes', () => {
    const echoed = `...${VALUE.slice(-ECHO_RUN)} was unparseable`;
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

  it('accepts the masked preview of a generic secret, which callers do print', () => {
    // Call the PRODUCT's mask, never a hand-rolled one. A locally built literal
    // asserts that a string this file constructed lacks a run of another string
    // this file constructed — true by construction, and it stays true however
    // maskMatch changes. Wired here, widening maskMatch's generic branch goes
    // red HERE, where the reason is written down, rather than in a caller that
    // reads like an unrelated regression.
    //
    // @akasecurity/plugin-sdk re-exports it, so this crosses no package wall —
    // src/triage/judge.ts imports maskText the same way.
    expect(refuses(maskMatch(VALUE), VALUE)).toBe(false);
  });

  it('passes over empty bytes — the limit that makes a positive control mandatory', () => {
    // Not a defect to fix here: `''` genuinely contains nothing. It is why a
    // caller must never point this at a capture that can come back empty
    // without also pinning that the capture is live.
    expect(refuses('', VALUE)).toBe(false);
  });
});

describe('errorFrom', () => {
  it('returns the thrown error', () => {
    const err = errorFrom(() => {
      throw new Error('boom');
    });
    expect(err?.message).toBe('boom');
  });

  it('returns undefined when nothing throws, which expectNoEchoOf then refuses', () => {
    // This is the whole reason the helper exists. The shape it replaces —
    // `try { f(); throw new Error('expected f to throw') } catch (e) { … }` —
    // catches the test's OWN error, so a caller asserting only absence stays
    // green while `f` stopped throwing entirely. Here `undefined` reaches
    // expectNoEchoOf's toBeDefined() guard and goes red.
    const err = errorFrom(() => 'returned normally');
    expect(err).toBeUndefined();
    expect(refuses(err?.message, VALUE)).toBe(true);
  });
});
