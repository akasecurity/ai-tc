import { readFileSync } from 'node:fs';
import { posix, win32 } from 'node:path';

import type {
  ManagedContext,
  ManagedSettingKey,
  ManagedSettings,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  MANAGED_SETTINGS_FILENAME,
  ManagedSettings as ManagedSettingsSchema,
  MODEL_JUDGE_PAYLOAD_VERSION,
  NO_MANAGED_CONTEXT,
  VAULT_CONSENT_VERSION,
} from '@akasecurity/schema';

import { parseJsonObject } from './internal/json.ts';

// The administrative overlay over ~/.aka/settings/settings.json.
//
// AKA READS this file and never writes it. That is the property that keeps the
// settings lock story intact: settings.json has exactly two writers, both
// holding the same advisory lock, and a third would reopen the lost-update hole
// for both. The administrator's tool owns this file; AKA overlays what it finds.
//
// It is a plain file read, so it costs no network hop — the whole point of
// sourcing managed configuration this way rather than from a control plane.

/**
 * Where an administrator's tool is expected to place the managed file, in
 * precedence order (first readable wins).
 *
 * These are the conventional machine-wide, administrator-writable locations per
 * platform. They sit OUTSIDE `~/.aka` deliberately: a path inside the user's own
 * home is one the user can edit, which would make a "lock" the locked party can
 * remove. Enforcing the file's ownership and mode is the operating system's job
 * and the administrator's — AKA cannot meaningfully verify it from inside a
 * process the user already controls, and pretending otherwise would be security
 * theatre. What this buys is honesty on screen and a single place to look.
 */
export function managedSettingsPaths(platform: NodeJS.Platform = process.platform): string[] {
  // Each branch joins with the SEPARATOR OF THE PLATFORM IT DESCRIBES, never
  // with the bare `join` of whichever host is running. `path.join` is
  // host-relative, so building the Windows path on a POSIX host yields
  // `C:\/ProgramData/...` — a string that is not a valid path anywhere. The
  // function takes `platform` precisely so both branches can be driven from
  // either host, and that is worth nothing if one of them is only correct at
  // home.
  if (platform === 'darwin') {
    return [
      posix.join('/Library', 'Application Support', 'AKASecurity', MANAGED_SETTINGS_FILENAME),
      posix.join('/Library', 'Managed Preferences', MANAGED_SETTINGS_FILENAME),
    ];
  }
  if (platform === 'win32') {
    // ProgramData is the machine-wide, administrator-writable root. Resolved
    // from its conventional location rather than the environment: reading
    // `%ProgramData%` here would need a `n/no-process-env` opt-out for a value
    // that is fixed on every supported install.
    return [win32.join('C:\\', 'ProgramData', 'AKASecurity', MANAGED_SETTINGS_FILENAME)];
  }
  return [posix.join('/etc', 'aka', MANAGED_SETTINGS_FILENAME)];
}

/**
 * Read the managed file, or null when no administrator has placed one.
 *
 * Fully fail-open, like readWorkspaceSettings: a missing, unreadable or
 * malformed file yields null rather than throwing, because this sits on the
 * plugin's fail-open hook path. That posture cuts one specific way and it is
 * worth being explicit about it — a corrupt managed file means the machine runs
 * UNMANAGED rather than refusing to run. The alternative (fail closed on a
 * damaged administrative file) turns a typo in an MDM payload into every hook
 * on every managed machine breaking at once, which is a far worse outcome than
 * a lock that has to be noticed and repaired.
 */
export function readManagedSettings(
  paths: string[] = managedSettingsPaths(),
): ManagedSettings | null {
  for (const path of paths) {
    let text: string;
    try {
      text = readFileSync(path, 'utf8');
    } catch {
      continue; // absent or unreadable — try the next location
    }
    const record = parseJsonObject(text);
    if (!record) continue;
    const parsed = ManagedSettingsSchema.safeParse(record);
    if (parsed.success) return parsed.data;
  }
  return null;
}

/** What the managed layer wants callers to render, derived from the file. */
export function managedContextOf(managed: ManagedSettings | null): ManagedContext {
  if (!managed) return NO_MANAGED_CONTEXT;
  // `organization` is spread in only when present: under
  // exactOptionalPropertyTypes an explicit `undefined` is not the same as an
  // absent key, and ManagedContext declares it optional rather than nullable.
  return {
    present: true,
    ...(managed.organization === undefined ? {} : { organization: managed.organization }),
    lockedFields: managed.lockedFields,
  };
}

/**
 * Overlay an administrator's pinned values onto the user's own settings.
 *
 * A pinned value wins over the user's, whether or not the key is also locked:
 * the two are separable on purpose (a value with no lock is a DEFAULT the user
 * may then change; a lock with no value freezes whatever they last chose).
 *
 * The two consents are the interesting case. They are stored as dated grant
 * records, and an administrator states an ANSWER rather than a record — so a
 * `true` materialises a grant stamped at read time at the current payload
 * version, and a `false` clears it outright. An administrator therefore cannot
 * forge a user's acknowledgement, and cannot pin a grant against a payload
 * version that has since moved: a bumped version re-invalidates an
 * administratively-granted consent exactly as it does a user's own, which is
 * what keeps "widening the payload invalidates old consents" true on managed
 * machines too.
 */
export function overlayManagedSettings(
  settings: WorkspaceSettings,
  managed: ManagedSettings | null,
  now: () => Date = () => new Date(),
): WorkspaceSettings {
  if (!managed) return settings;
  const { values } = managed;
  const merged: WorkspaceSettings = { ...settings };

  if (values.runMode !== undefined) merged.runMode = values.runMode;
  if (values.controlPlane !== undefined) {
    merged.controlPlane = {
      ...values.controlPlane,
      // The administrator pinned WHICH deployment, not WHEN this machine
      // joined it. Keep the user's own attach time when the endpoint is
      // unchanged, so a managed machine does not appear to re-attach on every
      // read; stamp a fresh one when the administrator moved it.
      attachedAt:
        settings.controlPlane?.endpoint === values.controlPlane.endpoint
          ? settings.controlPlane.attachedAt
          : now().toISOString(),
    };
  }
  if (values.historicalAccess !== undefined) merged.historicalAccess = values.historicalAccess;
  if (values.vaultKeyCustody !== undefined) merged.vaultKeyCustody = values.vaultKeyCustody;
  if (values.vaultInlineReveal !== undefined) merged.vaultInlineReveal = values.vaultInlineReveal;
  if (values.dataSharesInPlace !== undefined) merged.dataSharesInPlace = values.dataSharesInPlace;
  if (values.redactFallback !== undefined) merged.redactFallback = values.redactFallback;

  if (values.vaultConsent !== undefined) {
    merged.vaultConsent = values.vaultConsent
      ? // Keep an existing valid grant so its acknowledgedAt survives; mint one
        // at the current version otherwise.
        settings.vaultConsent?.version === VAULT_CONSENT_VERSION
        ? settings.vaultConsent
        : { acknowledgedAt: now().toISOString(), version: VAULT_CONSENT_VERSION }
      : undefined;
  }
  if (values.modelJudgeConsent !== undefined) {
    merged.modelJudgeConsent = values.modelJudgeConsent
      ? settings.modelJudgeConsent?.payloadVersion === MODEL_JUDGE_PAYLOAD_VERSION
        ? settings.modelJudgeConsent
        : {
            acknowledgedAt: now().toISOString(),
            payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION,
          }
      : undefined;
  }
  return merged;
}

/**
 * The keys a caller is refusing to write, given what an administrator locked.
 * Returns the locked subset of what was asked for — empty when the write is
 * entirely the user's to make.
 */
export function lockedAmong(
  context: ManagedContext,
  requested: readonly ManagedSettingKey[],
): ManagedSettingKey[] {
  if (!context.present) return [];
  return requested.filter((key) => context.lockedFields.includes(key));
}
