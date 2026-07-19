import { describe, expect, it } from 'vitest';

import { SetupHandoffOffer } from '../src/zod/setup-frame.ts';

// The no-findings / plain dashboard-handoff payload: the two
// fixed options and nothing else.
const PLAIN_OFFER = {
  worthALook: 0,
  options: [
    { id: 'open-dashboard', label: 'Open dashboard' },
    { id: 'not-now', label: 'Not now' },
  ],
};

// The live-key composed payload: the chain-entry option
// composed with — never replacing — the dashboard handoff. `liveKeys` is the
// surfaced live-key secret count that gates the composition (> 0 here).
const COMPOSED_OFFER = {
  worthALook: 5,
  liveKeys: 3,
  options: [
    { id: 'enter-remediation', label: 'Review leaked keys' },
    { id: 'open-dashboard', label: 'Open dashboard' },
    { id: 'not-now', label: 'Not now' },
  ],
};

describe('SetupHandoffOffer — the frame 0.6 handoff-offer payload', () => {
  it('validates the plain dashboard-handoff payload unchanged (additive, no reshape)', () => {
    const parsed = SetupHandoffOffer.safeParse(PLAIN_OFFER);
    expect(parsed.success).toBe(true);
  });

  it('validates the composed live-key payload: chain entry alongside Open dashboard + Not now', () => {
    const parsed = SetupHandoffOffer.safeParse(COMPOSED_OFFER);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    // The dashboard handoff stays reachable exactly as on the no-findings branch.
    expect(parsed.data.options.map((o) => o.id)).toEqual([
      'enter-remediation',
      'open-dashboard',
      'not-now',
    ]);
  });

  it('rejects a reordered plain offer (fixed-tuple discipline)', () => {
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 0,
        options: [
          { id: 'not-now', label: 'Not now' },
          { id: 'open-dashboard', label: 'Open dashboard' },
        ],
      }).success,
    ).toBe(false);
  });

  it('rejects a composed offer whose dashboard handoff was dropped (never replaces it)', () => {
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 3,
        options: [
          { id: 'enter-remediation', label: 'Review leaked keys' },
          { id: 'not-now', label: 'Not now' },
        ],
      }).success,
    ).toBe(false);
  });

  it('rejects a composed offer with a reordered chain-entry option', () => {
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 5,
        liveKeys: 3,
        options: [
          { id: 'open-dashboard', label: 'Open dashboard' },
          { id: 'enter-remediation', label: 'Review leaked keys' },
          { id: 'not-now', label: 'Not now' },
        ],
      }).success,
    ).toBe(false);
  });

  it('rejects a payload whose liveKeys exceeds worthALook (liveKeys is a subset)', () => {
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 3,
        liveKeys: 5,
        options: [
          { id: 'enter-remediation', label: 'Review leaked keys' },
          { id: 'open-dashboard', label: 'Open dashboard' },
          { id: 'not-now', label: 'Not now' },
        ],
      }).success,
    ).toBe(false);
  });

  it('validates a plain offer with important-but-no-secret findings (worthALook > 0, no live keys → no chain entry)', () => {
    // The all-category surfaced count is positive but no live-key secret
    // surfaced, so no chain entry is offered — the count that gates remediation
    // is the live-key count, not worthALook.
    const parsed = SetupHandoffOffer.safeParse({
      worthALook: 3,
      liveKeys: 0,
      options: [
        { id: 'open-dashboard', label: 'Open dashboard' },
        { id: 'not-now', label: 'Not now' },
      ],
    });
    expect(parsed.success).toBe(true);
  });

  it('rejects a positive-live-key offer that drops the chain entry (silent-omission guard)', () => {
    // liveKeys > 0 but the remediation option is missing: a harness must not
    // accept a payload that silently omits remediation when live keys surfaced.
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 5,
        liveKeys: 3,
        options: [
          { id: 'open-dashboard', label: 'Open dashboard' },
          { id: 'not-now', label: 'Not now' },
        ],
      }).success,
    ).toBe(false);
  });

  it('rejects a composed offer that omits its live-key count (chain entry with liveKeys 0)', () => {
    // The chain entry is present but no live keys are declared (liveKeys absent
    // ⇒ 0): a fabricated remediation offer must fail validation.
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 5,
        options: [
          { id: 'enter-remediation', label: 'Review leaked keys' },
          { id: 'open-dashboard', label: 'Open dashboard' },
          { id: 'not-now', label: 'Not now' },
        ],
      }).success,
    ).toBe(false);
  });
});
