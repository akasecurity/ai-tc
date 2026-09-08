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
});
