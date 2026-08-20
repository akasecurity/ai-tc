import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type {
  ManagedContext,
  ManagedSettingKey,
  ManagedSettings,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  defaultWorkspaceSettings,
  isModelJudgeConsentValid,
  isVaultConsentValid,
  WorkspaceSettings as WorkspaceSettingsSchema,
} from '@akasecurity/schema';

import { withFileLock } from './file-lock.ts';
import { parseJsonObject } from './internal/json.ts';
import { defaultDataDir, settingsDir } from './local-layout.ts';
import {
  lockedAmong,
  managedContextOf,
  overlayManagedSettings,
  readManagedSettings,
} from './managed-settings.ts';
import { ensureDataDirSync, writeOwnerOnlyFileSync } from './paths.ts';

// Read/write of ~/.aka/settings/settings.json, shared by every local consumer
// — plugin hooks, the CLI, and the web-ui; the SDK re-exports these. The
// env-dependent half of config loading (provider resolution) stays in the SDK,
// which composes these readers into its PluginConfig. A config.json written by
// an earlier release may sit alongside settings.json; nothing reads it.

export const SETTINGS_FILENAME = 'settings.json';

/**
 * Read settings.json under the base, default-filled when absent. Fully
 * fail-open: a missing or corrupt file yields unonboarded defaults rather than
 * throwing — this sits on the plugin's fail-open hook path. A pure reader with no
 * side effects: the at-rest mode is self-healed by the write/init/loadConfig
 * paths (see `aka init`'s ungated tighten and `loadConfig`), not on every read,
 * so a web-ui page render never chmods.
 */
export function readWorkspaceSettings(base: string = defaultDataDir()): WorkspaceSettings {
  // The administrator's overlay is applied HERE, not only on the surfaces that
  // render it. Every gate in the product — the vault's `isConsented`, the
  // judge's egress check, the history sweep, the Data Shares kill-switch —
  // resolves its answer through this function, so an overlay applied anywhere
  // narrower would change what the dashboard DISPLAYS while changing nothing
  // about what the machine DOES. That is worse than having no managed layer at
  // all: it tells an administrator a control is enforced when it is not.
  return overlayManagedSettings(readUserSettings(base), cachedManagedSettings());
}

// Read once per process. Every hook invocation is its own short-lived process,
// so this is one stat-and-miss per event rather than per call — and a hook that
// reads settings several times pays for the absent file once. A long-lived
// reader (the dashboard server) therefore holds an administrator's file from
// startup; that is the same staleness `settings.json` itself has there, and the
// alternative is a filesystem hit on a path that does not exist on the
// overwhelming majority of machines, on the fail-open capture path.
let managedCache: { value: ManagedSettings | null } | undefined;

function cachedManagedSettings(): ManagedSettings | null {
  managedCache ??= { value: readManagedSettings() };
  return managedCache.value;
}

/**
 * Forget the memoized administrative overlay. Exists for tests and for a
 * long-lived process that wants to pick up an administrator's change without a
 * restart; nothing on the capture path calls it.
 */
export function resetManagedSettingsCache(): void {
  managedCache = undefined;
}

/**
 * The user's own file, with NO administrative overlay applied.
 *
 * The write path reads through this rather than the public reader, and the
 * distinction is load-bearing: `applyOnboarding` merges over `current`, so an
 * overlaid `current` would persist the ADMINISTRATOR's pinned values into the
 * user's own file as though the user had chosen them. The overlay would then
 * survive the managed file being removed, which is the one thing a lock must
 * never do.
 */
function readUserSettings(base: string): WorkspaceSettings {
  const record = readJson(join(settingsDir(base), SETTINGS_FILENAME));
  if (!record) return defaultWorkspaceSettings();
  try {
    // The schema default-fills every missing key, so an older settings.json
    // written before a new field was added still parses.
    return WorkspaceSettingsSchema.parse(record);
  } catch {
    // Corrupt/invalid → behave as unonboarded rather than break the hook path.
    return defaultWorkspaceSettings();
  }
}

/** The settings actually in force, plus what the administrative layer pinned. */
export interface EffectiveSettings {
  settings: WorkspaceSettings;
  managed: ManagedContext;
}

/**
 * The settings in force on this machine: the user's file with any
 * administrator's overlay applied, alongside enough about that overlay to
 * render a locked control honestly.
 *
 * Deliberately a SEPARATE reader rather than a change to readWorkspaceSettings.
 * That one is called on every hook invocation and is the fail-open path; making
 * it read a second file on every call would put a new failure mode under every
 * capture for a value most machines do not have. Callers that must respect an
 * administrator — the dashboard's settings surface, and the writer below —
 * reach for this one.
 *
 * `managedOverride` is the injection seam: the real locations are absolute
 * system paths, so nothing else could exercise the overlay against a temp home.
 * Passing `null` reads a machine with no administrator.
 */
export function readEffectiveSettings(
  base: string = defaultDataDir(),
  managedOverride?: ManagedSettings | null,
): EffectiveSettings {
  const managed = managedOverride === undefined ? readManagedSettings() : managedOverride;
  return {
    settings: overlayManagedSettings(readUserSettings(base), managed),
    managed: managedContextOf(managed),
  };
}

/**
 * The answers to apply, either directly or derived from what is already on
 * disk. The function form is the one to reach for whenever an answer depends on
 * a current value — it runs INSIDE the write lock, so the settings it is handed
 * are the ones the merge is about to be applied to. Reading first and passing a
 * plain object puts that read outside the lock, which is the lost update this
 * writer exists to prevent, one caller further out.
 */
export type OnboardingAnswers =
  Partial<WorkspaceSettings> | ((current: WorkspaceSettings) => Partial<WorkspaceSettings>);

/**
 * Persist onboarding answers to settings.json (the /aka:setup writer, and the
 * web-ui settings page). Merges over the existing file so each edit is
 * additive, re-validates through the versioned schema, and stamps onboardedAt
 * on first completion so `onboarded` flips true. Owner-only atomic write (tmp +
 * rename), so a settings.json (or a leftover `.tmp` from an earlier crash) that
 * pre-existed with looser permissions ends 0600 rather than carrying its mode
 * through the rename — see writeOwnerOnlyFileSync.
 *
 * The read, the merge and the write are ONE critical section, held against
 * every other process on the machine (see withFileLock). tmp+rename alone makes
 * each publish indivisible but leaves the pair of them interleavable: the
 * wizard and the dashboard's Settings page are separate processes over one
 * file, and without the lock both read the same bytes and the second rename
 * discards the first one's answers with nothing raised at either end. The
 * fields at stake include the vault and model-judge consent grants, where the
 * lost write can be a REVOCATION — silently reinstating an egress the user
 * just withdrew.
 *
 * Throws rather than writing unlocked if the lock cannot be taken (see
 * FileLockError). Both callers surface that: the wizard exits non-zero with the
 * message, and the Settings action renders a save failure.
 */
export class ManagedFieldError extends Error {
  readonly fields: readonly ManagedSettingKey[];
  constructor(fields: readonly ManagedSettingKey[]) {
    super(`refusing to write administratively locked settings: ${fields.join(', ')}`);
    this.name = 'ManagedFieldError';
    this.fields = fields;
  }
}

// Which WorkspaceSettings keys a write would actually CHANGE, expressed as the
// managed key set. Only keys an administrator can lock are named — a write
// touching anything else is unaffected by the overlay.
//
// Compared by VALUE against what is on disk, never by key presence. The
// dashboard posts every field it renders on every save, whether or not the user
// touched it, so a presence test reports all four as touched on every save —
// and a single locked field would then refuse a change to any of the others.
// That would collapse the per-field lock this whole layer exists to express
// into an all-or-nothing one, while the UI went on showing the untouched rows
// as editable.
//
// `vaultConsent` and `modelJudgeConsent` collapse to the ANSWER they represent
// (granted or not), because that is the granularity an administrator pins: a
// caller re-sending an equivalent grant with a fresh acknowledgedAt has not
// changed the answer and must not be refused.
function lockableKeysTouched(
  current: WorkspaceSettings,
  applied: Partial<WorkspaceSettings>,
): ManagedSettingKey[] {
  const keys: ManagedSettingKey[] = [];
  const changed = (key: keyof WorkspaceSettings): boolean =>
    key in applied && applied[key] !== current[key];

  // The connection is one lockable unit: clearing the descriptor detaches just
  // as surely as clearing the mode (isAttached needs both), so either moving
  // counts as touching `runMode`.
  const connectionChanged =
    changed('runMode') ||
    ('controlPlane' in applied &&
      applied.controlPlane?.endpoint !== current.controlPlane?.endpoint);
  if (connectionChanged) keys.push('runMode');

  if (changed('historicalAccess')) keys.push('historicalAccess');
  if (changed('vaultKeyCustody')) keys.push('vaultKeyCustody');
  if (changed('vaultInlineReveal')) keys.push('vaultInlineReveal');
  if (changed('dataSharesInPlace')) keys.push('dataSharesInPlace');

  // Grants compare on whether one is in force, not on the record's identity.
  if (
    'vaultConsent' in applied &&
    isVaultConsentValid(applied.vaultConsent) !== isVaultConsentValid(current.vaultConsent)
  ) {
    keys.push('vaultConsent');
  }
  if (
    'modelJudgeConsent' in applied &&
    isModelJudgeConsentValid(applied.modelJudgeConsent) !==
      isModelJudgeConsentValid(current.modelJudgeConsent)
  ) {
    keys.push('modelJudgeConsent');
  }
  return keys;
}

// Drop every WorkspaceSettings key an administrator has locked. The inverse of
// lockableKeysTouched, and deliberately written out rather than derived from it:
// that one maps settings keys ONTO managed keys (many-to-one — `runMode` covers
// `controlPlane` too), and inverting a many-to-one map in the head is how one of
// the pair ends up covering a field the other does not.
function withoutLockedKeys(
  applied: Partial<WorkspaceSettings>,
  managed: ManagedContext,
): Partial<WorkspaceSettings> {
  if (!managed.present || managed.lockedFields.length === 0) return applied;
  const out = { ...applied };
  const locked = (key: ManagedSettingKey): boolean => managed.lockedFields.includes(key);
  if (locked('runMode')) {
    delete out.runMode;
    delete out.controlPlane;
  }
  if (locked('historicalAccess')) delete out.historicalAccess;
  if (locked('vaultConsent')) delete out.vaultConsent;
  if (locked('vaultKeyCustody')) delete out.vaultKeyCustody;
  if (locked('vaultInlineReveal')) delete out.vaultInlineReveal;
  if (locked('modelJudgeConsent')) delete out.modelJudgeConsent;
  if (locked('dataSharesInPlace')) delete out.dataSharesInPlace;
  return out;
}

export function applyOnboarding(
  answers: OnboardingAnswers,
  base: string = defaultDataDir(),
  managedOverride?: ManagedSettings | null,
): WorkspaceSettings {
  const dir = settingsDir(base);
  // Ahead of the lock, not inside it: the lock file is a sibling of
  // settings.json, so the directory has to exist before one can be taken.
  ensureDataDirSync(dir);
  const file = join(dir, SETTINGS_FILENAME);
  const managedSettings = managedOverride === undefined ? readManagedSettings() : managedOverride;
  const managed = managedContextOf(managedSettings);
  return withFileLock(file, () => {
    // The RAW file, never the overlaid view — see readUserSettings. Merging over
    // an overlay would write the administrator's pins into the user's own file.
    const current = readUserSettings(base);
    const applied = typeof answers === 'function' ? answers(current) : answers;
    // A locked field is judged against what the user was SHOWN, not against
    // their own file, and the two differ exactly when an administrator pinned a
    // value. The dashboard renders the effective settings and posts every field
    // back, so on such a machine a locked field arrives carrying the
    // ADMINISTRATOR's value — which against the raw file reads as a change.
    //
    // Comparing against the raw file is wrong in BOTH directions, and the second
    // is the dangerous one: an echo of the pin was refused (so every save on a
    // managed machine failed, including saves of entirely unlocked fields),
    // while a user posting their OWN value for a locked field matched the raw
    // file, counted as no change, and went through — the lock enforcing nothing.
    const effective = overlayManagedSettings(current, managedSettings);
    const refused = lockedAmong(managed, lockableKeysTouched(effective, applied));
    if (refused.length > 0) throw new ManagedFieldError(refused);
    const merged = WorkspaceSettingsSchema.parse({
      ...current,
      // Locked keys are stripped rather than merged. Everything still here is,
      // by the refusal above, an unchanged ECHO of the administrator's value —
      // so dropping it discards no answer of the user's, and writing it would
      // persist the pin into their file, where it would outlive the managed
      // file and read as their own choice once the lock was gone.
      ...withoutLockedKeys(applied, managed),
      // First setup stamps the time; later edits keep the original completion mark.
      onboardedAt: applied.onboardedAt ?? current.onboardedAt ?? new Date().toISOString(),
    });
    writeOwnerOnlyFileSync(file, `${JSON.stringify(merged, null, 2)}\n`);
    return merged;
  });
}

function readJson(file: string): Record<string, unknown> | null {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  return parseJsonObject(text) ?? null;
}
