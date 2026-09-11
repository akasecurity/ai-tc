import { describe, expect, it } from 'vitest';

import type { ManagedContext } from '../../src/zod/managed.ts';
import {
  isFieldManaged,
  managedByLabel,
  ManagedSettings,
  NO_MANAGED_CONTEXT,
} from '../../src/zod/managed.ts';

// The two helpers every surface words an administrative lock through. They are
// tiny, and that is the point: a dashboard, a CLI and a plugin that each decided
// for themselves what "locked" looked like would show one mechanism three ways.

describe('isFieldManaged', () => {
  it('locks only the keys an administrator named', () => {
    const ctx: ManagedContext = { present: true, lockedFields: ['runMode', 'vaultConsent'] };
    expect(isFieldManaged(ctx, 'runMode')).toBe(true);
    expect(isFieldManaged(ctx, 'vaultConsent')).toBe(true);
    expect(isFieldManaged(ctx, 'historicalAccess')).toBe(false);
  });

  it('locks nothing when no administrator is present', () => {
    expect(isFieldManaged(NO_MANAGED_CONTEXT, 'runMode')).toBe(false);
  });

  it('is gated on `present`, not merely on the list being empty', () => {
    // A context carrying locked fields while absent must still lock nothing —
    // otherwise a stale or half-built context silently freezes controls.
    const contradictory: ManagedContext = { present: false, lockedFields: ['runMode'] };
    expect(isFieldManaged(contradictory, 'runMode')).toBe(false);
  });
});

describe('managedByLabel', () => {
  it('names the organization when the administrator supplied one', () => {
    expect(managedByLabel({ present: true, organization: 'Acme', lockedFields: [] })).toContain(
      'Acme',
    );
  });

  it('still attributes the decision when no name was supplied', () => {
    // The fallback has to stay a sentence about an administrator. A locked
    // control with a blank attribution reads as a bug rather than a policy.
    const label = managedByLabel(NO_MANAGED_CONTEXT);
    expect(label).toMatch(/your organization/i);
    expect(label).not.toContain('undefined');
  });
});

describe('ManagedSettings parsing', () => {
  it('default-fills an administrator file that names only what it pins', () => {
    const parsed = ManagedSettings.parse({ values: { runMode: 'attached' } });
    expect(parsed.lockedFields).toEqual([]);
    expect(parsed.specVersion).toBeGreaterThan(0);
  });

  it('keeps the locks it knows and reports the ones it does not', () => {
    // The lockable set is an explicit enum rather than keyof WorkspaceSettings,
    // so a name outside it is never honoured — `onboardedAt` is bookkeeping and
    // `notASetting` is a typo. But neither may cost the file its OTHER locks:
    // this is the shape an older build sees when an administrator locks a key
    // a newer build added, and refusing the file there ran that build
    // unmanaged with every pin and lock gone.
    const parsed = ManagedSettings.parse({
      lockedFields: ['runMode', 'onboardedAt', 'notASetting'],
    });
    expect(parsed.lockedFields).toEqual(['runMode']);
    expect(parsed.unknownLockedFields).toEqual(['onboardedAt', 'notASetting']);
  });

  it('reports no unknown locks at all when every lock is known', () => {
    // Absent rather than empty: the ordinary file carries no key for it, so a
    // consumer spreading the result carries none either.
    const parsed = ManagedSettings.parse({ lockedFields: ['runMode'] });
    expect(parsed.lockedFields).toEqual(['runMode']);
    expect(parsed).not.toHaveProperty('unknownLockedFields');
  });

  it('still refuses a lockedFields that is not a list of names', () => {
    // Tolerance is for a NAME this build does not know, not for a shape it
    // cannot read. A string or a number here is a damaged file.
    expect(ManagedSettings.safeParse({ lockedFields: 'runMode' }).success).toBe(false);
    expect(ManagedSettings.safeParse({ lockedFields: [1] }).success).toBe(false);
  });

  it('refuses an empty endpoint on a pinned connection', () => {
    expect(ManagedSettings.safeParse({ values: { controlPlane: { endpoint: '' } } }).success).toBe(
      false,
    );
  });

  it('keeps a pin it knows and reports one it does not', () => {
    // The mirror of the lock case above, and the half that used to be silent:
    // a plain `z.object` drops an unrecognised key and succeeds, so this pin
    // vanished with nothing anywhere saying so.
    const parsed = ManagedSettings.parse({
      values: { runMode: 'attached', notASetting: true, alsoNew: 'x' },
    });

    expect(parsed.values).toEqual({ runMode: 'attached' });
    expect(parsed.unknownValueFields).toEqual(['notASetting', 'alsoNew']);
  });

  it('reports no unknown pins at all when every pin is known', () => {
    const parsed = ManagedSettings.parse({ values: { runMode: 'attached' } });

    expect(parsed.values).toEqual({ runMode: 'attached' });
    expect(parsed).not.toHaveProperty('unknownValueFields');
  });

  it('still refuses a BAD value under a key it does know', () => {
    // The line between tolerance and damage, and the reason the split re-runs
    // the nested schema rather than calling `.strict()` or trusting the record.
    // Without this a typo'd enum would be kept as an unparsed value or dropped
    // as unknown, and either way the administrator's decision is not applied
    // and the file still reads as healthy.
    const bad = ManagedSettings.safeParse({ values: { runMode: 'attachd' } });

    expect(bad.success).toBe(false);
    expect(bad.error?.issues[0]?.path).toEqual(['values', 'runMode']);
  });

  it('refuses a values that is not an object at all', () => {
    // Same boundary the lockedFields shape case draws: tolerance is for a NAME
    // this build does not know, never for a shape it cannot read.
    expect(ManagedSettings.safeParse({ values: 'runMode' }).success).toBe(false);
    expect(ManagedSettings.safeParse({ values: [1] }).success).toBe(false);
  });

  it('tolerates an unknown pin and an unknown lock in one file, separately', () => {
    // The shape a mid-upgrade fleet really produces: the newer build's key
    // both pinned and locked. Both halves are reported, and neither is folded
    // into the other — an unapplied lock and an unapplied pin have different
    // consequences for the administrator reading the notice.
    const parsed = ManagedSettings.parse({
      values: { runMode: 'attached', newerKey: 1 },
      lockedFields: ['runMode', 'newerKey'],
    });

    expect(parsed.values).toEqual({ runMode: 'attached' });
    expect(parsed.lockedFields).toEqual(['runMode']);
    expect(parsed.unknownValueFields).toEqual(['newerKey']);
    expect(parsed.unknownLockedFields).toEqual(['newerKey']);
  });
});
