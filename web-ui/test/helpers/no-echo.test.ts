import { maskMatch } from '@akasecurity/detections';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { ECHO_RUN, expectNoEchoOf } from './no-echo.ts';

// The helper an absence assertion leans on gets its own suite, or it can be
// weakened back with nothing going red: raise ECHO_RUN past the value's length,
// or empty the loop, and every caller keeps passing while proving nothing. This
// package's action suite is 86 tests and every one of them stayed green with
// ECHO_RUN set to 64 before this file existed.
//
// The fixture comes from the bundled rule's own `examples`, so no secret-shaped
// literal lives in this file and the value stays in step with the rule.
const RULE_ID = 'secrets/aws-access-key';
const example = bundledDetections()
  .flatMap((p) => p.rules)
  .find((r) => r.id === RULE_ID)?.examples?.[0];
if (example === undefined) throw new Error(`bundled rule ${RULE_ID} has no example`);
const VALUE: string = example;

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

  it('refuses an undefined haystack — an action that never errored proves nothing', () => {
    expect(refuses(undefined, VALUE)).toBe(true);
  });

  it('accepts the masked preview of a generic secret, which is stored on purpose', () => {
    // Call the PRODUCT's mask, never a hand-rolled one: a locally built literal
    // asserts that a string this file constructed lacks a run of another string
    // this file constructed, which is true by construction however maskMatch
    // changes. Widen its generic branch past two revealed characters and this
    // goes red HERE, where the reason is written down.
    expect(refuses(maskMatch(VALUE), VALUE)).toBe(false);
  });

  it('refuses an email preview — why this is scoped to generic secrets', () => {
    // maskMatch's email branch reveals the WHOLE domain, and a single-character
    // local part returns the input unchanged. Both fill the window on purpose,
    // so a surface printing a pii/email preview is out of scope for this helper
    // rather than a leak it found.
    const email = 'user@example.com';
    expect(maskMatch(email)).toContain('example.com');
    expect(refuses(maskMatch(email), email)).toBe(true);
    expect(maskMatch('a@b.com')).toBe('a@b.com');
  });

  it('passes over empty bytes — the limit that makes a positive control mandatory', () => {
    // Not a defect to fix here: `''` genuinely contains nothing. It is why a
    // caller must never point this at a capture that can come back empty
    // without also pinning that the capture is live.
    expect(refuses('', VALUE)).toBe(false);
  });
});
