import { getLoadedRules, maskMatch } from '@akasecurity/detections';
import { registerBundledPacks } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { ECHO_RUN, expectNoEchoOf } from './no-echo.ts';

// The helper an absence assertion leans on gets its own suite, or it can be
// weakened back with nothing going red: raise ECHO_RUN past the value's length,
// or empty the loop, and every caller keeps passing while proving nothing. Each
// case here fails if that happens.
//
// The fixture comes from the bundled rule's own `examples`, so no secret-shaped
// literal lives in this file and the value stays in step with the rule.
registerBundledPacks();
const GENERIC = getLoadedRules().find((r) => r.id === 'secrets/aws-access-key')?.examples?.[0];
if (GENERIC === undefined) throw new Error('bundled rule secrets/aws-access-key has no example');
const VALUE: string = GENERIC;

// maskMatch's generic branch reveals the first and last character around six
// fixed asterisks. That is two characters, but they sit in two runs of ONE —
// and the RUN is the number that matters here, because expectNoEchoOf's window
// slides over contiguous slices. Two characters that are never adjacent cannot
// fill a window of any width; two adjacent ones start eating into it.
const GENERIC_PREVIEW_RUN = 1;

// The pii fixture both email cases below share: one calibrates the measurement
// against a branch that discloses a long run, the other pins that such a preview
// is refused. They must describe the SAME value or neither says what it claims.
const EMAIL = 'user@example.com';

// The longest contiguous run of `raw` that `preview` discloses, derived rather
// than read off the mask's current output — a literal here would assert that a
// string this file built lacks a run of another string this file built, which
// is the shape CLAUDE.md forbids for exactly this reason.
function longestRevealedRun(preview: string, raw: string): number {
  let longest = 0;
  for (let i = 0; i < raw.length; i += 1) {
    // A preview holding raw.slice(i, i + len) holds every shorter slice from
    // the same start, so the first miss ends this start's search.
    for (let len = longest + 1; i + len <= raw.length; len += 1) {
      if (!preview.includes(raw.slice(i, i + len))) break;
      longest = len;
    }
  }
  return longest;
}

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
    // A caller's comment cites this number as the reason a masked preview is
    // safe to print. Move it and that reasoning has to be re-derived.
    expect(ECHO_RUN).toBe(8);
    expect(VALUE.length).toBeGreaterThan(ECHO_RUN);
  });

  // The three cases below are the whole point: each output leaks a live
  // credential's run, and each one passes the weaker whole-value form. The
  // control assertion in each is what proves the new form is STRONGER rather
  // than merely also-red — without it a green helper and a green predecessor
  // look identical.
  it('refuses a prefix echo that a whole-value assertion passes', () => {
    const echoed = `did you mean ${VALUE.slice(0, ECHO_RUN)}...?`;
    expect(refuses(echoed, VALUE)).toBe(true);
    expect(echoed).not.toContain(VALUE); // control: the form this replaced stays green
  });

  it('refuses a tail echo that a whole-value assertion passes', () => {
    const echoed = `...${VALUE.slice(-ECHO_RUN)} was not found`;
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
    // The coexistence the CLI's stdout assertions depend on: a generic secret's
    // preview reveals its first and last character around fixed asterisks, so it
    // cannot fill the window. This pins that the preview is safe TODAY. It does
    // NOT pin how much margin is left — see the case below, which is the one
    // that holds the number the callers reason about.
    expect(refuses(maskMatch(VALUE), VALUE)).toBe(false);
  });

  it('measures a revealed run — the instrument the margin pin below is read on', () => {
    // Calibration, kept as its own case so its failure names the INSTRUMENT
    // rather than the pin it feeds. An implementation that always answered "one"
    // would hold the margin pin green for ever — this rule's own failure mode,
    // one level down — and from inside that pin the two are indistinguishable.
    // maskMatch's email branch reveals the '@' and the WHOLE domain after it, so
    // the measurement has to report exactly that run here.
    expect(longestRevealedRun(maskMatch(EMAIL), EMAIL)).toBe(EMAIL.length - EMAIL.indexOf('@'));
  });

  it("reveals a run of one — the margin the CLI's stdout binding spends", () => {
    // The acceptance case above fires only once a preview holds a contiguous run
    // of ECHO_RUN characters, so it stays green through every widening from two
    // revealed characters up to seven. That band is exactly where a usability
    // change lands ("show enough of the value to tell two blocked secrets
    // apart"), and it is the band in which the CLI's stdout binding quietly
    // loses the margin its own comment claims.
    //
    // So the margin is pinned here, derived from maskMatch, and it goes red on
    // the FIRST character of widening. detections/test/mask.test.ts also reddens
    // on that change, but its failure reads as "you changed the mask, update the
    // expectation" and says nothing about a downstream safety argument moving.
    // This one goes red where that argument is written down.
    expect(longestRevealedRun(maskMatch(VALUE), VALUE)).toBe(GENERIC_PREVIEW_RUN);
    expect(GENERIC_PREVIEW_RUN).toBeLessThan(ECHO_RUN);
  });

  it('refuses an email preview — why the stdout rule is scoped to generic secrets', () => {
    // maskMatch's email branch reveals the WHOLE domain, and a single-character
    // local part returns the input unchanged. Both fill the window legitimately,
    // so a surface printing a pii/email preview is out of scope for this helper
    // rather than a leak it found.
    expect(maskMatch(EMAIL)).toContain('example.com');
    expect(refuses(maskMatch(EMAIL), EMAIL)).toBe(true);
    expect(maskMatch('a@b.com')).toBe('a@b.com');
  });

  it('passes over empty bytes — the limit that makes a positive control mandatory', () => {
    // Not a defect to fix here: `''` genuinely contains nothing. It is why a
    // caller must never point this at a capture that can come back empty
    // without also pinning that the capture is live.
    expect(refuses('', VALUE)).toBe(false);
  });
});
