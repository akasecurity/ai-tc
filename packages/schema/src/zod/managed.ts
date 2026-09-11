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
    //
    // Parsed as a RECORD rather than as the nested schema, and split below for
    // the same reason `lockedFields` is parsed as names: a plain `z.object`
    // drops an unrecognised key and succeeds, so a pin this build does not know
    // vanished and nothing anywhere said so. A pin with no lock is a supported
    // shape — it is a DEFAULT the user may still change — so that silence hit
    // exactly the file an administrator is most likely to write while a fleet
    // is mid-upgrade.
    //
    // Splitting here rather than calling `.strict()`: strict would REFUSE the
    // file, which is the outcome the lock half already rejected — an older
    // build then runs entirely unmanaged, every pin and lock gone. A bad KNOWN
    // value still fails, because the nested schema is re-run over the known
    // subset and its issues are re-raised on this parse.
    values: z.record(z.string(), z.unknown()).default({}),
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
  .transform(({ lockedFields, values, ...rest }, ctx) => {
    const known: ManagedSettingKey[] = [];
    const unknown: string[] = [];
    for (const name of lockedFields) {
      if (isManagedSettingKey(name)) known.push(name);
      else unknown.push(name);
    }

    // `Object.hasOwn`, never `name in shape`: `in` consults the PROTOTYPE CHAIN,
    // so every `Object.prototype` name — `toString`, `constructor`, `valueOf`,
    // `__proto__` and the rest — classifies as known, is handed to the nested
    // schema, and is dropped there with nothing reported. That is exactly the
    // silence this split exists to end, reached from the one direction the
    // split itself created.
    //
    // `__proto__` specifically never reaches here: the `z.record` above strips
    // it, so a pin by that name is neither applied nor reported. That is Zod's
    // behaviour rather than this function's, and it is the safe direction — but
    // it IS one more silently dropped pin, so do not read the split below as
    // covering it.
    //
    // The accumulator is null-prototype anyway. Nothing can reach it through
    // `__proto__` today, and that is a property of the parser above rather than
    // of this loop; a plain `{}` here would make the loop's correctness depend
    // on it.
    const knownValues = Object.create(null) as Record<string, unknown>;
    const unknownValues: string[] = [];
    for (const [name, value] of Object.entries(values)) {
      if (Object.hasOwn(ManagedSettingsValues.shape, name)) knownValues[name] = value;
      else unknownValues.push(name);
    }
    const pinned = ManagedSettingsValues.safeParse(knownValues);
    if (!pinned.success) {
      // Re-raised on THIS parse, under the `values` path, so a typo in a key
      // this build does know is still a damaged file rather than a silently
      // dropped pin. Losing that refusal is what makes the tolerance above
      // dangerous instead of merely forgiving.
      for (const issue of pinned.error.issues)
        ctx.addIssue({ ...issue, path: ['values', ...issue.path] });
      return z.NEVER;
    }

    // Each unknown list is present only when non-empty, so the ordinary file
    // carries no key for it and a consumer spreading the result carries none.
    return {
      ...rest,
      values: pinned.data,
      lockedFields: known,
      ...(unknown.length > 0 ? { unknownLockedFields: unknown } : {}),
      ...(unknownValues.length > 0 ? { unknownValueFields: unknownValues } : {}),
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
  // HOW MANY locks and HOW MANY pinned values this build does not know, so a
  // surface can say an administrator set something it is not applying.
  //
  // COUNTS rather than the names, because this context is handed to a client
  // component and is therefore serialized to the browser on every settings
  // render: `lockedFields` is bounded by the enum, while the names are whatever
  // the administrator's file happens to contain. Nothing is lost by counting —
  // every consumer reads `.length` — and the names stay on the parsed
  // `ManagedSettings` for a reader that wants them.
  //
  // Two numbers rather than one, and neither inferred from the other, because
  // the consequences differ: an unapplied LOCK leaves a control the
  // administrator meant to freeze still editable, while an unapplied PIN leaves
  // a default they meant to set unset. A surface may say both in one sentence;
  // it may not derive one from the other. Each is absent when it is zero.
  unknownLockedCount?: number;
  unknownValueCount?: number;
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
