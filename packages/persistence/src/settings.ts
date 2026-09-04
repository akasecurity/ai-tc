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
  //
  // READ LIVE, deliberately not memoized. A per-process cache was tried and is
  // wrong for the same reason this reader exists: `tokenize.ts`'s consent gate
  // calls this on EVERY tokenize precisely "so a revocation applies to the very
  // next call, not the next process", and caching the managed half breaks that
  // for an ADMINISTRATIVE revocation — the one an operator is least able to
  // work around, since they cannot restart a user's dashboard. It also split
  // the three read paths, leaving this one stale while readEffectiveSettings
  // and applyOnboarding re-read. The cost is one or two ENOENT stats beside a
  // settings.json read that is already happening on the same call.
  return overlayManagedSettings(readUserSettings(base), readManagedSettings());
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
 * A separate reader from readWorkspaceSettings NOT because the overlay is
 * narrower there — it is not, that one applies it too — but because this one
 * additionally reports the administrative CONTEXT. A caller that only needs the
 * values in force reaches for readWorkspaceSettings; a caller that has to render
 * or refuse a locked control needs to know which keys are locked and who locked
 * them, and that is what this returns.
 *
 * This paragraph previously argued the opposite — that readWorkspaceSettings
 * must not read a second file per call — and was left standing when that is
 * exactly what it now does, deliberately. See the comment there for why a
 * per-process cache was wrong: an administrative revocation has to apply to the
 * very next call, and caching split the three read paths.
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
  //
  // The WHOLE descriptor is compared, not just the endpoint. withoutManagedKeys
  // strips `controlPlane` entirely when runMode is locked, so a field this
  // comparison ignores is one a caller can change without being refused and
  // then have silently discarded — the write reporting success while the label
  // it was asked to set went nowhere. `attachedAt` is excluded deliberately: it
  // is stamped server-side on every attach, so including it would make an
  // otherwise-identical re-attach read as a change.
  const descriptorChanged =
    'controlPlane' in applied &&
    (applied.controlPlane?.endpoint !== current.controlPlane?.endpoint ||
      applied.controlPlane?.label !== current.controlPlane?.label);
  if (changed('runMode') || descriptorChanged) keys.push('runMode');

  if (changed('historicalAccess')) keys.push('historicalAccess');
  if (changed('vaultKeyCustody')) keys.push('vaultKeyCustody');
  if (changed('vaultInlineReveal')) keys.push('vaultInlineReveal');
  if (changed('dataSharesInPlace')) keys.push('dataSharesInPlace');
  if (changed('redactFallback')) keys.push('redactFallback');

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

// Which keys an administrator supplied a VALUE for, whether or not they also
// locked it. Derived from the file rather than from the lock list, because a
// pin and a lock are deliberately separable.
function pinnedKeys(managed: ManagedSettings | null): ManagedSettingKey[] {
  if (!managed) return [];
  const { values } = managed;
  const keys: ManagedSettingKey[] = [];
  if (values.runMode !== undefined || values.controlPlane !== undefined) keys.push('runMode');
  if (values.historicalAccess !== undefined) keys.push('historicalAccess');
  if (values.vaultConsent !== undefined) keys.push('vaultConsent');
  if (values.vaultKeyCustody !== undefined) keys.push('vaultKeyCustody');
  if (values.vaultInlineReveal !== undefined) keys.push('vaultInlineReveal');
  if (values.modelJudgeConsent !== undefined) keys.push('modelJudgeConsent');
  if (values.dataSharesInPlace !== undefined) keys.push('dataSharesInPlace');
  if (values.redactFallback !== undefined) keys.push('redactFallback');
  return keys;
}

// Drop every administratively-supplied key this write does not actually CHANGE.
//
// It stripped only LOCKED keys, which left the other supported configuration
// leaking: a pinned value with no lock is "a DEFAULT the user may then change",
// and the form echoes it back on every save — so the administrator's answer
// landed in the user's own file, where it outlived the managed file and read as
// their choice. For `vaultConsent` that is a real recorded custody grant, with
// an acknowledgedAt the user never gave.
//
// `touched` is passed in rather than recomputed so the strip and the refusal can
// never disagree about what "changed" means. A LOCKED key reaching here is an
// echo by construction — the refusal already rejected any real change — while a
// PINNED key that genuinely changed is the user exercising a default, and is
// written untouched.
function withoutManagedKeys(
  applied: Partial<WorkspaceSettings>,
  managed: ManagedContext,
  pinned: readonly ManagedSettingKey[],
  touched: readonly ManagedSettingKey[],
): Partial<WorkspaceSettings> {
  if (!managed.present) return applied;
  const strip = (key: ManagedSettingKey): boolean =>
    (managed.lockedFields.includes(key) || pinned.includes(key)) && !touched.includes(key);

  const out = { ...applied };
  if (strip('runMode')) {
    delete out.runMode;
    delete out.controlPlane;
  }
  if (strip('historicalAccess')) delete out.historicalAccess;
  if (strip('vaultConsent')) delete out.vaultConsent;
  if (strip('vaultKeyCustody')) delete out.vaultKeyCustody;
  if (strip('vaultInlineReveal')) delete out.vaultInlineReveal;
  if (strip('modelJudgeConsent')) delete out.modelJudgeConsent;
  if (strip('dataSharesInPlace')) delete out.dataSharesInPlace;
  if (strip('redactFallback')) delete out.redactFallback;
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
    const touched = lockableKeysTouched(effective, applied);
    const refused = lockedAmong(managed, touched);
    if (refused.length > 0) throw new ManagedFieldError(refused);
    const merged = WorkspaceSettingsSchema.parse({
      ...current,
      // Locked keys are stripped rather than merged. Everything still here is,
      // by the refusal above, an unchanged ECHO of the administrator's value —
      // so dropping it discards no answer of the user's, and writing it would
      // persist the pin into their file, where it would outlive the managed
      // file and read as their own choice once the lock was gone.
      ...withoutManagedKeys(applied, managed, pinnedKeys(managedSettings), touched),
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
