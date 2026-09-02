import { KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { policyMeta } from '../../src/detections/meta.ts';
import type { DetectionPolicyFloor } from '../../src/detections/policy-floor.ts';
import {
  effectivePolicyId,
  isPolicyGoverned,
  policyFloorReason,
  unavailableUnderFloor,
} from '../../src/detections/policy-floor.ts';

// The rule an attached machine's Detections page has to tell the truth about:
// the organization's policy is a FLOOR the device may raise and never lower,
// and a detection the organization has written a policy for is not the device's
// to re-assign at all.
//
// These are the decisions BOTH the picker and the list read, which is the point
// of them being one module: the defect this closes was a page that offered a
// weaker choice, accepted it, showed it as selected, and enforced something
// else — and a second copy of the comparison is how one of the two surfaces
// starts saying that again.

const floor = (over: Partial<DetectionPolicyFloor> = {}): DetectionPolicyFloor => ({
  floor: 'warn',
  locked: false,
  ...over,
});

describe('unavailableUnderFloor', () => {
  it('restricts nothing when there is no floor at all', () => {
    // The standalone machine — every OSS install that has not attached. It must
    // come out of this module with the control it had before any of it existed.
    expect(unavailableUnderFloor(null)).toBeUndefined();
    expect(unavailableUnderFloor(undefined)).toBeUndefined();
  });

  it('restricts nothing when the floor is the weakest archetype', () => {
    // A floor of Monitor forbids no choice, so offering the reason line anyway
    // would put an organizational constraint on screen where there is none.
    expect(unavailableUnderFloor(floor({ floor: 'monitor' }))).toBeUndefined();
  });

  it('restricts exactly what is weaker than the floor', () => {
    const restricted = unavailableUnderFloor(floor({ floor: 'warn' }));
    expect(Object.keys(restricted ?? {})).toEqual(['monitor']);
  });

  it('keeps Redact & Vault available under a Redact floor', () => {
    // The two archetypes enforce the same action and differ only on whether the
    // value can be recovered. A floor is a statement about ENFORCEMENT, so
    // ruling out the reversible one would refuse a choice that satisfies it.
    const restricted = unavailableUnderFloor(floor({ floor: 'redact' }));
    expect(Object.keys(restricted ?? {}).sort()).toEqual(['monitor', 'warn']);
    // Positive control on the same call: the assertion above would also pass if
    // the function had returned a map missing every key.
    expect(restricted?.monitor).toBe(policyFloorReason(floor({ floor: 'redact' })));
  });

  it('takes every option when the detection is locked, including the current one', () => {
    // A lock is not a minimum — the organization stated the answer. Leaving the
    // selected archetype clickable would offer a write that is refused, which is
    // the exact shape this work exists to remove.
    const restricted = unavailableUnderFloor(floor({ floor: 'warn', locked: true }));
    expect(Object.keys(restricted ?? {}).sort()).toEqual([...KNOWN_BUILTIN_IDS].sort());
  });

  it('gives every restricted option the SAME sentence', () => {
    // The picker dedupes its reason lines by string, so one constraint must
    // render one line rather than one per option.
    const restricted = unavailableUnderFloor(floor({ floor: 'block' }));
    expect(new Set(Object.values(restricted ?? {})).size).toBe(1);
  });
});

describe('policyFloorReason', () => {
  it('names the archetype the organization requires', () => {
    // A floor the user cannot name is one they cannot act on.
    expect(policyFloorReason(floor({ floor: 'redact' }))).toContain(policyMeta('redact').label);
  });

  it('says the choice is the organization’s, and that raising it is still allowed', () => {
    const reason = policyFloorReason(floor({ floor: 'warn' }));
    expect(reason).toMatch(/organization/i);
    expect(reason).toMatch(/stronger/i);
  });

  it('says a locked detection cannot be changed here at all', () => {
    // The remedy differs: under a floor there is still a decision to take, under
    // a lock there is none. A reader who cannot tell which they are in goes
    // looking for a stronger option that will also be refused.
    const reason = policyFloorReason(floor({ locked: true }));
    expect(reason).toMatch(/cannot be changed/i);
    expect(reason).not.toMatch(/stronger/i);
  });

  it('does not read as a failure the user should retry', () => {
    // Retrying cannot help and the user has done nothing wrong.
    for (const state of [floor(), floor({ locked: true })]) {
      expect(policyFloorReason(state)).not.toMatch(/error|failed|try again/i);
    }
  });

  it('says something different for a lock than for a floor', () => {
    expect(policyFloorReason(floor({ locked: true }))).not.toBe(policyFloorReason(floor()));
  });
});

describe('effectivePolicyId', () => {
  it('is the stored assignment when nothing constrains it', () => {
    expect(effectivePolicyId('warn', null)).toBe('warn');
    expect(effectivePolicyId(undefined, null)).toBe('monitor');
  });

  it('raises a stored assignment that is below the floor', () => {
    // The case a refusal at the write path cannot reach: a store written before
    // this machine was attached. Enforcement raises it, so the page must too.
    expect(effectivePolicyId('monitor', floor({ floor: 'warn' }))).toBe('warn');
  });

  it('leaves an assignment at or above the floor alone', () => {
    expect(effectivePolicyId('block', floor({ floor: 'warn' }))).toBe('block');
    expect(effectivePolicyId('warn', floor({ floor: 'warn' }))).toBe('warn');
    // Vault satisfies a Redact floor, so the user's custody choice survives.
    expect(effectivePolicyId('vault', floor({ floor: 'redact' }))).toBe('vault');
  });

  it('treats an unassigned detection as the Monitor it resolves to', () => {
    expect(effectivePolicyId(undefined, floor({ floor: 'block' }))).toBe('block');
  });

  it('treats an id no archetype claims as below the floor', () => {
    // Enforcement ranks an unrecognised action below everything, so a custom id
    // shown as-is would be the one pill on the page still claiming something
    // weaker than what runs.
    expect(effectivePolicyId('some-custom-policy', floor({ floor: 'warn' }))).toBe('warn');
  });
});

describe('isPolicyGoverned', () => {
  it('is false with no floor', () => {
    expect(isPolicyGoverned('monitor', null)).toBe(false);
  });

  it('is false when the local choice already satisfies the floor', () => {
    // Nothing was taken away, so marking the row would claim a constraint the
    // user is not under.
    expect(isPolicyGoverned('block', floor({ floor: 'warn' }))).toBe(false);
  });

  it('is true when the floor raised what the row shows', () => {
    expect(isPolicyGoverned('monitor', floor({ floor: 'warn' }))).toBe(true);
  });

  it('is true for a lock even when the two already agree', () => {
    // The value is right and the decision is still not this machine's. A row
    // that looked ordinary would send the user to the picker to find that out.
    expect(isPolicyGoverned('warn', floor({ floor: 'warn', locked: true }))).toBe(true);
  });
});
