import { KNOWN_BUILTIN_IDS, PackPolicyFloor } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { policyMeta } from '../../src/detections/meta.ts';
import type { DetectionPolicyFloor } from '../../src/detections/policy-floor.ts';
import {
  DETECTION_STAYS_ON_REASON,
  effectivePolicyId,
  isDisableRefused,
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

describe('DetectionPolicyFloor', () => {
  it('is the schema shape the store states its answer in, not a look-alike', () => {
    // The floor is computed on the server — it needs the local store and the
    // machine's settings — and arrives here as a plain prop. That hand-off is
    // only verbatim while the two names denote ONE shape: the assignments below
    // are the pin, and either of them stops compiling the moment a side grows a
    // field the other does not have. A separate declaration would have kept the
    // views compiling while dropping it.
    const fromStore = PackPolicyFloor.parse({ floor: 'redact', locked: false });
    const asProp: DetectionPolicyFloor = fromStore;
    const backToStore: PackPolicyFloor = asProp;

    expect(backToStore).toEqual(fromStore);
    // And the decisions actually run off that value, rather than off a shape
    // this test built for itself.
    expect(Object.keys(unavailableUnderFloor(asProp) ?? {}).sort()).toEqual(['monitor', 'warn']);
  });
});

describe('isDisableRefused', () => {
  it('refuses nothing on a machine nothing manages', () => {
    // Every OSS install that has not attached. The toggle must come out of this
    // module exactly as live as it was before any of it existed.
    expect(isDisableRefused(true, null)).toBe(false);
    expect(isDisableRefused(true, undefined)).toBe(false);
  });

  it('refuses the switch-off under EVERY floor, the weakest included', () => {
    // The whole difference from the picker's question. There the floor names a
    // rung and the archetypes below it are restricted; here "off" is below the
    // ladder, so what matters is that the organization spoke for this detection
    // at all.
    for (const id of KNOWN_BUILTIN_IDS) {
      expect(isDisableRefused(true, floor({ floor: id })), `a floor of '${id}'`).toBe(true);
    }
  });

  it('parts company with the picker exactly at a Monitor floor', () => {
    // The case that would be missed by reusing unavailableUnderFloor: a floor of
    // Monitor forbids no ASSIGNMENT, and still forbids switching the detection
    // off. Both halves asserted, so this cannot pass by both being empty.
    expect(unavailableUnderFloor(floor({ floor: 'monitor' }))).toBeUndefined();
    expect(isDisableRefused(true, floor({ floor: 'monitor' }))).toBe(true);
  });

  it('never refuses a re-enable, locked or not', () => {
    // Re-enabling moves toward what the organization asked for. A store can hold
    // a detection switched off from before any of this existed, and withholding
    // the toggle there would leave it stuck off with nothing able to turn it
    // back on.
    for (const locked of [false, true]) {
      expect(isDisableRefused(false, floor({ locked })), `locked: ${String(locked)}`).toBe(false);
    }
  });
});

describe('DETECTION_STAYS_ON_REASON', () => {
  it('names whose decision it is and what is still open', () => {
    // A user who is not told the organization decided this goes looking for a
    // broken toggle; one who is not told enforcement can still be raised reads
    // the whole detection as out of their hands.
    expect(DETECTION_STAYS_ON_REASON).toMatch(/organization/i);
    expect(DETECTION_STAYS_ON_REASON).toMatch(/stronger/i);
  });

  it('does not read as a fault to retry', () => {
    expect(DETECTION_STAYS_ON_REASON).not.toMatch(/error|failed|try again/i);
  });

  it("is not the picker's sentence", () => {
    // Different constraints with different remedies. Collapsing them would tell
    // someone whose detection may not be switched off to go and pick a stronger
    // archetype, which is not what was refused.
    for (const locked of [false, true]) {
      expect(DETECTION_STAYS_ON_REASON).not.toBe(policyFloorReason(floor({ locked })));
    }
  });
});
