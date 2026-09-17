import { describe, expect, it } from 'vitest';

import {
  assertRawFree,
  edgeTruncatedSpans,
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

// The longest contiguous run of `raw` that `text` holds, derived rather than read
// off a literal — a hand-written number here would pin this file's arithmetic
// instead of what the mask really discloses.
function longestRunShared(text: string, raw: string): number {
  let longest = 0;
  for (let i = 0; i < raw.length; i += 1) {
    for (let len = longest + 1; i + len <= raw.length; len += 1) {
      if (!text.includes(raw.slice(i, i + len))) break;
      longest = len;
    }
  }
  return longest;
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
  // to '***'.
  //
  // Read the second assertion as a CONSTRAINT on the run check, not as a settled
  // decision: it says the preview holds a window of its own raw, so any text
  // carrying BOTH the preview and that raw in `rawValues` would be refused. An
  // earlier version of this file stopped here and called it a decision, which is
  // how the plan document — which is exactly such a text — shipped refusing every
  // email hit. `carriesRawRun` now exempts a value's own preview, so the case
  // below asserts the boundary honours the constraint rather than tripping on it.
  it('reveals a window of its own raw — the constraint the run check honours', () => {
    const EMAIL = 'user@example.com';
    const preview = safeMaskedMatch(EMAIL);

    expect(preview).toBe('u***@example.com');
    // The preview holds a run of the raw — measured, not assumed.
    expect(longestRunShared(preview, EMAIL)).toBeGreaterThanOrEqual(8);
    // ...and the boundary does NOT refuse a document carrying it.
    expect(refuses(preview, [EMAIL])).toBe(false);
  });

  // The whole point of the exemption being SCOPED: a preview is not a licence to
  // carry the value it previews. Everything outside the preview still rejects.
  it('still refuses the local part a preview does not reveal', () => {
    const EMAIL = 'deploy@example.com';
    expect(refuses(`contact ${EMAIL} now`, [EMAIL])).toBe(true);
    expect(refuses(`near ${EMAIL.slice(0, 10)}`, [EMAIL])).toBe(true);
  });

  // A connection string takes the same email branch, so its preview reveals the
  // host — but never the password, which must still reject.
  it('still refuses a connection string password the preview hides', () => {
    const conn = ['smtp://alice', 'hunter2pass@mail.example.com'].join(':');
    expect(refuses(safeMaskedMatch(conn), [conn])).toBe(false); // the preview passes
    expect(refuses(`url ${conn}`, [conn])).toBe(true); // the whole value does not
    expect(refuses(`pw ${conn.slice(12, 24)}`, [conn])).toBe(true); // nor the password
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

  // Where the exemption draws the line, which is also what is left of the
  // tightening's false-positive cost. The preview is what the product discloses,
  // so text sharing a run with the DISCLOSED part is accepted and text sharing
  // one with the rest is refused.
  //
  // An earlier version of this case asserted the opposite of the first
  // assertion below — it pinned an unrelated domain mention as refused, and
  // called that the accepted cost. That was the plan-document defect wearing a
  // context-window costume: the same disclosure that makes this acceptable here
  // is what made the plan write throw for every email hit.
  it('accepts a run the preview discloses and refuses one it does not', () => {
    const email = 'deploy@example.com';
    const unrelated = 'see example.com/docs for the runbook';

    expect(unrelated).not.toContain(email); // no occurrence of the address itself
    // The domain is revealed by the preview, so its appearance discloses nothing
    // the product has not already shown.
    expect(safeMaskedMatch(email)).toContain('example.com');
    expect(refuses(unrelated, [email])).toBe(false);

    // The local part is NOT revealed, so a run covering it still rejects — and
    // the whole-value form this replaced passes it, which is the leak.
    const localRun = `audit trail for ${email.slice(0, 10)}`;
    expect(refuses(localRun, [email])).toBe(true);
    expect(wholeValueRejects(localRun, email)).toBe(false);
  });

  // A high-entropy secret keeps the strict behaviour end to end: its preview
  // reveals two non-adjacent characters, so essentially every window is outside
  // it and the exemption buys an attacker nothing.
  it('exempts almost nothing for a high-entropy value', () => {
    expect(refuses(`near ${RAW.slice(3, 11)}`, [RAW])).toBe(true);
    expect(shortestRejectedRun(RAW, boundaryRejects)).toBe(8);
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

// A fixed-radius context window cuts whatever straddles its edge, so a value
// present only as a bare prefix or suffix of itself is the ONE occurrence a
// caller's `indexOf` pass cannot find — there is no whole value to search for.
// That was inert while the verifier matched whole values; run by run it is the
// case the verifier rejects, so leaving it unspanned turns every such window
// into a guaranteed refusal.
describe('edgeTruncatedSpans', () => {
  const OTHER = 'Wk4Pq8Zn2Vb6Hm3Xr9Ts5Ld7Gc1Fj0A';

  it('spans a value the RIGHT edge cut, which indexOf cannot find', () => {
    const cut = OTHER.slice(0, 14);
    const text = `trailing ${cut}`;
    expect(text.indexOf(OTHER)).toBe(-1); // the premise: nothing whole to find
    const spans = edgeTruncatedSpans(text, [OTHER]);
    expect(spans).toHaveLength(1);
    expect(text.slice(spans[0]?.span.start, spans[0]?.span.end)).toBe(cut);
  });

  it('spans a value the LEFT edge cut', () => {
    const cut = OTHER.slice(10);
    const text = `${cut} leading`;
    expect(text.indexOf(OTHER)).toBe(-1);
    const spans = edgeTruncatedSpans(text, [OTHER]);
    expect(spans).toHaveLength(1);
    expect(text.slice(spans[0]?.span.start, spans[0]?.span.end)).toBe(cut);
  });

  it('spans nothing for a clipped run too short to fill a window', () => {
    // Seven characters cannot fill an eight-character window, so the verifier
    // does not reject it and spanning it would be over-redaction.
    const text = `tail ${OTHER.slice(0, 7)}`;
    expect(edgeTruncatedSpans(text, [OTHER])).toHaveLength(0);
  });

  it('spans nothing when the boundary shares no run with the value', () => {
    expect(edgeTruncatedSpans('nothing in common here at all', [OTHER])).toHaveLength(0);
  });

  // The whole point, driven at the shape the join builder really has: masking
  // spans this window's own hits, and the join-level check then reads the result
  // against EVERY value in the run. A neighbour the window clipped is in that
  // second list and in no span, so without these extra spans the pair refuses.
  it('is what lets the join-level check accept an edge-clipped neighbour', () => {
    const cut = OTHER.slice(0, 14);
    const text = `${RAW} then ${cut}`;
    const all = [RAW, OTHER];
    const whole = [{ rawMatch: RAW, span: { start: 0, end: RAW.length } }];

    // Without the edge spans: masking is clean, and the join-level read refuses.
    expect(() => assertRawFree(maskContextSlice(text, 0, whole), all)).toThrow(RawEgressError);

    // With them, the clipped run is covered and the same pair goes through.
    const withEdges = [...whole, ...edgeTruncatedSpans(text, all)];
    const masked = assertRawFree(maskContextSlice(text, 0, withEdges), all);
    expect(masked).not.toContain(cut);
  });

  // The throw carries the text masking had already produced, so a caller that
  // must not propagate it can blunt-redact THAT instead of starting over from
  // the raw input — which would discard every span the masker did cover.
  it('leaves the refusal carrying the partially masked text', () => {
    // A span that covers only part of its value is what this backstop is for.
    // The second hit's span lands correctly, so the masked text it produced is
    // worth strictly more than the raw input — which is why the error carries it.
    const text = `${RAW} then ${OTHER}`;
    const hits = [
      { rawMatch: RAW, span: { start: 0, end: 10 } }, // misaligned: leaves a run
      { rawMatch: OTHER, span: { start: text.indexOf(OTHER), end: text.length } },
    ];
    let err: unknown = null;
    try {
      maskContextSlice(text, 0, hits);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RawEgressError);
    const masked = (err as RawEgressError).masked;
    expect(masked).toBeDefined();
    // The span that DID land is preserved — the whole reason to blunt-redact
    // this rather than start over from the raw input.
    expect(masked).not.toContain(OTHER);
    expect(masked).toContain(RAW.slice(10)); // the live run it refused over
  });
});
