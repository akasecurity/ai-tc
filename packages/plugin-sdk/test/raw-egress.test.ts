import { describe, expect, it } from 'vitest';

import {
  assertRawFree,
  maskContextSlice,
  RawEgressError,
  safeMaskedMatch,
} from '../src/raw-egress.ts';

// High-entropy, and deliberately NOT credential-shaped: this repository is
// public, and the run cases below only need a value whose eight-character
// windows cannot collide with ordinary prose. An English-phrase literal would
// collide instead of catching a leak.
const RAW = 'Qx7Lm2Zv9Tw4Rk6Hd3Nf5Bp8Cs1Yg0J';

// Did the boundary refuse this text? A throw is the refusal, so "would have gone
// red" is observable without failing the case that asks. Only a RawEgressError
// counts: a bare `catch` would read a TypeError — the shape a crash on a
// malformed rawValues would take — as a successful containment, and every case
// built on this helper would stay green while the boundary was crashing.
function refuses(text: string, rawValues: readonly string[]): boolean {
  try {
    assertRawFree(text, rawValues);
    return false;
  } catch (e) {
    if (e instanceof RawEgressError) return true;
    throw e;
  }
}

// The shortest run of `raw` that `reject` refuses, MEASURED rather than read off
// a constant. A literal here would pin this file's own arithmetic; the number
// that matters is the one the boundary really enforces. The window is interior,
// so a refusal cannot be explained by a prefix or suffix special case, and it is
// never the whole value — so a check that rejects only whole values reports the
// sentinel rather than quietly reporting the whole length as if it were a run.
//
// `reject` is a PARAMETER so this one function answers two questions with two
// known-different answers (see the calibration case below). Measured against the
// product only, a stub that always returned 8 would hold the pin green for ever
// and be indistinguishable from a real measurement.
function shortestRejectedRun(raw: string, reject: (text: string, raw: string) => boolean): number {
  for (let len = 1; len < raw.length; len += 1) {
    if (reject(`diagnostic mentions ${raw.slice(1, 1 + len)} and stops there`, raw)) return len;
  }
  return raw.length; // sentinel: no partial run is refused at all
}

// The boundary under test, as a predicate.
const boundaryRejects = (text: string, raw: string): boolean => refuses(text, [raw]);

// The form the boundary replaced, as a predicate — the calibration baseline.
const wholeValueRejects = (text: string, raw: string): boolean => text.includes(raw);

describe('maskContextSlice', () => {
  it('rebases a span onto a slice with a nonzero start', () => {
    const full = '0123456789 the secret is SECRET1234 in this text';
    const sliceStart = 5;
    const slice = full.slice(sliceStart);
    const spanStart = full.indexOf('SECRET1234');
    const spanEnd = spanStart + 'SECRET1234'.length;

    const masked = maskContextSlice(slice, sliceStart, [
      { rawMatch: 'SECRET1234', span: { start: spanStart, end: spanEnd } },
    ]);

    expect(masked).not.toContain('SECRET1234');
    expect(masked).toContain('[REDACTED:SECRET]');
  });

  it('masks two secrets inside one window', () => {
    const slice = 'alpha SECRET1234 middle SECRET5678 omega';
    const firstStart = slice.indexOf('SECRET1234');
    const secondStart = slice.indexOf('SECRET5678');

    const masked = maskContextSlice(slice, 0, [
      {
        rawMatch: 'SECRET1234',
        span: { start: firstStart, end: firstStart + 'SECRET1234'.length },
      },
      {
        rawMatch: 'SECRET5678',
        span: { start: secondStart, end: secondStart + 'SECRET5678'.length },
      },
    ]);

    expect(masked).not.toContain('SECRET1234');
    expect(masked).not.toContain('SECRET5678');
  });

  it('throws RawEgressError when a stale span misses the raw value', () => {
    const slice = 'the value SECRET1234 leaked here';

    expect(() =>
      maskContextSlice(slice, 0, [{ rawMatch: 'SECRET1234', span: { start: 0, end: 3 } }]),
    ).toThrow(RawEgressError);
  });

  // maskContextSlice's backstop is tightened WITH assertRawFree rather than left
  // behind it. A span that covers only part of its value is the same defect as
  // one that misses it outright, and the whole-value form cannot see it: the
  // masked text no longer holds the entire value, so `includes` is satisfied
  // while a live run sits in the output.
  it('throws when a span covers only PART of its value, leaving a live run', () => {
    const slice = `the value ${RAW} leaked here`;
    const at = slice.indexOf(RAW);
    const half = Math.floor(RAW.length / 2);

    const thrown = (): string =>
      maskContextSlice(slice, 0, [{ rawMatch: RAW, span: { start: at, end: at + half } }]);

    expect(thrown).toThrow(RawEgressError);

    // The fixture has to be in the class under test, or the throw above could be
    // for some other reason. What redact leaves behind is the tail past the
    // span: it must be long enough to BE a run, and short of the whole value, so
    // that the form this replaced would have passed. Both are derived from the
    // span rather than modelling redact's output, which would be true by
    // construction and would stop tracking redact the moment it changed.
    const surviving = RAW.slice(half);
    expect(at).toBeGreaterThanOrEqual(0);
    expect(surviving.length).toBeGreaterThanOrEqual(8);
    expect(surviving).not.toBe(RAW);
    expect(wholeValueRejects(surviving, RAW)).toBe(false);
  });
});

describe('safeMaskedMatch', () => {
  it('falls back to *** for a short-local-part email', () => {
    expect(safeMaskedMatch('a@b.com')).toBe('***');
  });

  it('still masks an ordinary secret', () => {
    const masked = safeMaskedMatch('SECRET1234');
    expect(masked).not.toBe('SECRET1234');
    expect(masked).not.toContain('SECRET1234');
  });

  // The recorded decision for safeMaskedMatch, held as behaviour, not a comment.
  // This check is DELIBERATELY whole-value while its two siblings are run-by-run,
  // because it verifies a preview built to reveal a fragment ON PURPOSE. The
  // email branch reveals the whole domain, which is a run far past the window —
  // so tightening it in step with the others would collapse every email preview
  // to '***'. The second assertion is what makes that a measurement rather than
  // a claim: the same preview IS refused by the run-by-run sibling.
  it('keeps an email preview that the run-by-run siblings would refuse', () => {
    const EMAIL = 'user@example.com';
    const preview = safeMaskedMatch(EMAIL);

    expect(preview).toBe('u***@example.com');
    expect(refuses(preview, [EMAIL])).toBe(true);
  });

  // The other half of the same decision: a generic secret's preview reveals its
  // first and last character around fixed asterisks — two characters that are
  // never adjacent, so they sit in two runs of ONE and cannot fill a window at
  // any width. That is why the run check can be applied to text CARRYING such a
  // preview without refusing it.
  it('produces a generic preview that the run-by-run siblings accept', () => {
    expect(refuses(safeMaskedMatch(RAW), [RAW])).toBe(false);
  });
});

describe('assertRawFree', () => {
  it('passes clean text through unchanged', () => {
    expect(assertRawFree('nothing sensitive here', ['SECRET1234'])).toBe('nothing sensitive here');
  });

  it('throws when a raw value survives verbatim', () => {
    expect(() => assertRawFree('leaked SECRET1234 here', ['SECRET1234'])).toThrow(RawEgressError);
  });

  // The three cases below are the point of the tightening: each text leaks a
  // live run of a credential and each one PASSES the whole-value form. The
  // control in every case is what proves the new check is stronger rather than
  // merely also-red — without it a tightened boundary and its predecessor are
  // indistinguishable from inside the assertion.
  it('throws on a prefix run that a whole-value check passes', () => {
    const text = `judge blew up near ${RAW.slice(0, 8)}...`;
    expect(refuses(text, [RAW])).toBe(true);
    expect(text).not.toContain(RAW); // control: the form this replaced stays green
  });

  it('throws on a tail run that a whole-value check passes', () => {
    const text = `...${RAW.slice(-8)} was not found`;
    expect(refuses(text, [RAW])).toBe(true);
    expect(text).not.toContain(RAW);
  });

  it('throws on an interior run that a whole-value check passes', () => {
    const text = `near ${RAW.slice(5, 13)}`;
    expect(refuses(text, [RAW])).toBe(true);
    expect(text).not.toContain(RAW);
  });

  // The MIN_RAW_LEN..RAW_RUN_LEN band: a value shorter than one window cannot
  // fill one, so the sliding loop never runs and the whole-value fallback is the
  // only thing between this and a silent pass.
  it('throws on a short value echoed whole, which cannot fill a window', () => {
    const short = 'ab12cd';
    expect(short.length).toBeLessThan(8);
    expect(refuses(`unknown value ${short}`, [short])).toBe(true);
  });

  // Order independence across the two branches. The long value builds the window
  // index; if `text` is too short to hold one window that index is empty, and a
  // short value later in the list must still get its whole-value check. Both
  // orders are driven because only one of them exercises the empty-index path.
  it('refuses a short value that follows a long one over a sub-window text', () => {
    const short = 'ab12cd';
    const long = 'LONGVALUE1234567';
    expect(short.length).toBeLessThan(8);
    expect(short.length).toBeGreaterThanOrEqual(4);

    expect(refuses(short, [long, short])).toBe(true);
    expect(refuses(short, [short, long])).toBe(true);
  });

  // The floor itself, kept: below MIN_RAW_LEN a substring match is not
  // significant enough to act on, and tightening did not move that.
  it('ignores a value below the MIN_RAW_LEN floor', () => {
    expect(refuses('the abc of it', ['abc'])).toBe(false);
  });

  it('still passes clean text carrying no run at all', () => {
    expect(refuses('claude -p judge subprocess failed (exit 1)', [RAW])).toBe(false);
  });

  // The cost of the tightening, recorded rather than discovered later. A raw
  // value that shares a window with LEGITIMATE surrounding text is refused, and
  // for a low-entropy value that is reachable: an email hit's domain can appear
  // in a context window on its own, outside any occurrence of the address, so it
  // survives masking and trips this check where the whole-value form passed.
  //
  // That is the fail-safe direction and it is the intended trade-off — a refused
  // preview beats a leaked prefix — but it is a behaviour change, so it is
  // pinned here rather than left to be met as a bug report. It is also the
  // argument for keeping RAW_RUN_LEN at 8 rather than lowering it: every
  // character off the window makes this collision likelier.
  it('refuses text sharing a window with a LOW-ENTROPY value — the accepted cost', () => {
    const email = 'deploy@example.com';
    const unrelated = 'see example.com/docs for the runbook';

    expect(unrelated).not.toContain(email); // no occurrence to mask
    expect(refuses(unrelated, [email])).toBe(true);
    expect(wholeValueRejects(unrelated, email)).toBe(false); // the form this replaced passed
  });

  // The pin. It is DERIVED from the boundary, so it moves only when the boundary
  // does — and it goes red in every direction the number can drift:
  //
  //   widened to 9+  -> the measurement reports 9+, this reports the new value
  //   narrowed to 7  -> the measurement reports 7
  //   run check gone -> no partial run is refused, the sentinel comes back
  //
  // Eight is the number the test-side `no-echo` helpers use. They sit across a
  // package wall and are INDEPENDENT copies, so neither pins the other; this is
  // the product side's own pin, and widening it back is a deliberate act that
  // has to be argued here.
  it('refuses a run of eight — widening that back is a deliberate act', () => {
    expect(shortestRejectedRun(RAW, boundaryRejects)).toBe(8);
    expect(RAW.length).toBeGreaterThan(8);
  });

  // The calibration the pin above is read on, kept as its own case so its
  // failure names the INSTRUMENT rather than the pin it feeds. Driving the SAME
  // function with the form the boundary replaced has to report the sentinel: a
  // stub that always answered "8" passes the pin for ever, and from inside that
  // pin a real measurement and a constant are indistinguishable.
  it('reports the sentinel for the whole-value form it replaced', () => {
    expect(shortestRejectedRun(RAW, wholeValueRejects)).toBe(RAW.length);
  });
});
