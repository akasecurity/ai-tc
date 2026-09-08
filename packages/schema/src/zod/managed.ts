import { z } from 'zod';

import { RedactFallback } from './policy.ts';

// Administratively-supplied configuration: a second settings source that an
// MDM or config-management tool writes and AKA only ever READS.
//
// Read-only from AKA's side is the load-bearing property, not a simplification.
// settings.json has exactly two writers today and both hold the same advisory
// lock; a third writer reopens the lost-update hole for both. Keeping the
// managed file outside AKA's write set means there is no third writer to
// coordinate — the administrator's tool owns the file, AKA overlays it.
//
// Nothing here dials anything. This is a file on disk, so it costs no network
// hop and crosses none of the bans in the workspace lint config.

export const MANAGED_SETTINGS_FILENAME = 'managed-settings.json';

export const MANAGED_SETTINGS_SPEC_VERSION = 1;

// The settings keys an administrator may pin. Deliberately an explicit enum
// rather than `keyof WorkspaceSettings`: a field added to WorkspaceSettings
// tomorrow must be considered before it becomes remotely lockable, and deriving
// this would grant that silently. `onboardedAt` and `specVersion` are absent on
// purpose — they are bookkeeping, not policy.
export const ManagedSettingKey = z
  .enum([
    'runMode',
    'historicalAccess',
    'vaultConsent',
    'vaultKeyCustody',
    'vaultInlineReveal',
    'modelJudgeConsent',
    'dataSharesInPlace',
    'redactFallback',
  ])
  .meta({ id: 'ManagedSettingKey' });
export type ManagedSettingKey = z.infer<typeof ManagedSettingKey>;

/** Whether a name in an administrator's file is a key this build can lock. */
export function isManagedSettingKey(value: string): value is ManagedSettingKey {
  return ManagedSettingKey.safeParse(value).success;
}

// The values an administrator may pin, as a partial overlay. Each is the same
// shape WorkspaceSettings carries for that key, so an overlay cannot introduce
// a value the settings schema would reject.
//
// `vaultConsent` and `modelJudgeConsent` are booleans HERE while
// WorkspaceSettings stores dated grant records: an administrator states the
// answer, and the overlay materialises a grant stamped at read time. An admin
// cannot forge a user's acknowledgement timestamp, and a `false` is a hard
// denial the user cannot re-grant while it is locked.
export const ManagedSettingsValues = z
  .object({
    runMode: z.enum(['standalone', 'attached']).optional(),
    controlPlane: z
      .object({
        endpoint: z.string().min(1),
        label: z.string().min(1).optional(),
      })
      .optional(),
    historicalAccess: z.enum(['full', 'session-only']).optional(),
    vaultConsent: z.boolean().optional(),
    vaultKeyCustody: z.enum(['file', 'keychain']).optional(),
    vaultInlineReveal: z.enum(['masked', 'full', 'off']).optional(),
    modelJudgeConsent: z.boolean().optional(),
    dataSharesInPlace: z.boolean().optional(),
    redactFallback: RedactFallback.optional(),
  })
  .meta({ id: 'ManagedSettingsValues' });
export type ManagedSettingsValues = z.infer<typeof ManagedSettingsValues>;

export const ManagedSettings = z
  .object({
    specVersion: z.number().int().positive().default(MANAGED_SETTINGS_SPEC_VERSION),
    // Shown on every locked control, so the user can tell an administrative
    // decision from a bug. Absent renders as a generic "your organization".
    organization: z.string().min(1).optional(),
    // What the administrator pinned.
    values: ManagedSettingsValues.default({}),
    // Which of those the user may not change. A key here with no matching value
    // freezes whatever the user last chose; a value with no lock is a DEFAULT
    // the user may still override. The two are separable on purpose.
    //
    // Parsed as NAMES rather than as the enum, and split below: a name this
    // build does not know is dropped from the locked set and reported, never a
    // reason to refuse the file. The same shape reaches an older build whenever
    // an administrator locks a key a newer build added, and refusing it there
    // ran that build entirely unmanaged — every pin and lock gone — on exactly
    // the fleets most likely to carry a version skew. A name outside the enum
    // is still never HONOURED: the lockable set stays explicit above.
    lockedFields: z.array(z.string()).default([]),
  })
  .transform(({ lockedFields, ...rest }) => {
    const known: ManagedSettingKey[] = [];
    const unknown: string[] = [];
    for (const name of lockedFields) {
      if (isManagedSettingKey(name)) known.push(name);
      else unknown.push(name);
    }
    // The unknown list is present only when non-empty, so the ordinary file
    // carries no key for it and a consumer spreading the result carries none.
    return {
      ...rest,
      lockedFields: known,
      ...(unknown.length > 0 ? { unknownLockedFields: unknown } : {}),
    };
  })
  .meta({ id: 'ManagedSettings' });
export type ManagedSettings = z.infer<typeof ManagedSettings>;

// What every consumer sees after the overlay: the settings actually in force,
// plus enough about the administrative layer to render it honestly. Carrying
// the locked set rather than a single boolean is what lets the dashboard lock
// one control and leave its neighbour editable.
export interface ManagedContext {
  // Whether any managed file was found and parsed at all.
  present: boolean;
  organization?: string;
  lockedFields: readonly ManagedSettingKey[];
  // Names the administrator locked that this build does not know, so a
  // surface can say a lock exists that it is not applying. Absent when there
  // are none.
  unknownLockedFields?: readonly string[];
}

export const NO_MANAGED_CONTEXT: ManagedContext = { present: false, lockedFields: [] };

/** Whether an administrator has frozen this key. */
export function isFieldManaged(context: ManagedContext, key: ManagedSettingKey): boolean {
  return context.present && context.lockedFields.includes(key);
}

/**
 * The label for a locked control. One function so every surface — dashboard,
 * CLI, plugin — words an administrative lock identically; a user who sees two
 * different phrasings for one mechanism reads them as two mechanisms.
 */
export function managedByLabel(context: ManagedContext): string {
  return `Managed by ${context.organization ?? 'your organization'}`;
}
