import { parseArgs } from 'node:util';

import {
  dataDir,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readEffectiveSettings,
  settingsDir,
} from '@akasecurity/persistence';
import type { ManagedSettings, SyncLaneRetention, WorkspaceSettings } from '@akasecurity/schema';
import {
  attachmentModeOf,
  BodyRetention,
  isAttached,
  isFieldManaged,
  managedByLabel,
  resolveScope,
  syncLaneRetentionOf,
} from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import type { Prompter } from '../lib/prompter.ts';
import { terminalPrompter } from '../lib/prompter.ts';

// `aka prune` — run local body expiry now, instead of waiting for a session to
// trigger it.
//
// What it clears is `audit_events.content`: the prompt, reply, tool output or
// scanned file text a capture recorded. What it never touches is the row, its
// timestamps and severity, or any finding derived from it — so the security
// history the dashboard reads is unchanged and only the raw bodies go.
//
// It is a no-op unless body expiry is switched on in settings, because expiry is
// off by default and this command is not a way to bypass that. `--dry-run`
// reports what a pass would free and is safe to run on any machine.

const USAGE = `Usage: aka prune [--dry-run] [--days <n>]

Expire captured bodies past the retention horizon. Keeps every event row and
every finding — only the raw prompt/reply/tool/file text is cleared.

  --dry-run     Report what would be freed; change nothing.
  --days <n>    Override the horizon for this run only.
  --home <dir>  Use this AKA home instead of ~/.aka.
`;

const DAY_MS = 86_400_000;

// The legal horizon is `BodyRetention`'s own field, so `--days` accepts exactly
// the windows the settings write accepts and the refusal names that range.
const RETAIN_DAYS = BodyRetention.shape.retainDays.unwrap();

function fmtBytes(n: number): string {
  if (n < 1024) return `${String(n)} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i] ?? 'GB'}`;
}

/**
 * What the sync lane may lose on this machine, from the settings in force and
 * the attachment mode its credential records.
 *
 * The mode is read off the credential, not the settings, because that is where
 * an attachment records it and no settings writer can remove it.
 * `syncLaneRetentionOf` owns the answer; this only gathers its two inputs. The
 * background retention pass has the same helper, written the same way: they are
 * two copies, so they must stay identical, and both suites pin the same four
 * states (scoped, machine, unparseable credential, read that throws).
 *
 * TOTAL, and every failure holds. An attachment whose credential cannot be read
 * resolves to no scope, which `syncLaneRetentionOf` reads as hold-all, and a
 * throw anywhere here is hold-all too — this command has no catch of its own
 * further out, and a crash would only hide the decision from the user.
 */
function syncLaneRetentionFor(settings: WorkspaceSettings, base: string): SyncLaneRetention {
  try {
    const connection = settings.controlPlane;
    if (!isAttached(settings) || connection === undefined) {
      return syncLaneRetentionOf(settings, undefined);
    }
    const read = readControlPlaneCredentialFile(settingsDir(base), connection);
    if (!read.usable) return syncLaneRetentionOf(settings, undefined);
    return syncLaneRetentionOf(
      settings,
      resolveScope({
        mode: attachmentModeOf(read.credential),
        scope: settings.attachmentScope,
        endpoint: connection.endpoint,
      }),
    );
  } catch {
    return { kind: 'hold-all' };
  }
}

export function runPrune(
  argv: string[],
  io: Prompter = terminalPrompter(),
  // The administrator's file, for tests. `undefined` reads the real system
  // locations, exactly as `applyOnboarding`'s own override does; `null` is an
  // explicitly unmanaged machine.
  managedOverride?: ManagedSettings | null,
): void {
  let values: {
    home?: string | undefined;
    'dry-run'?: boolean | undefined;
    days?: string | undefined;
  };
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        ...HOME_OPTION,
        'dry-run': { type: 'boolean' },
        days: { type: 'string' },
      },
      allowPositionals: false,
    }));
  } catch {
    io.err(USAGE);
    return;
  }

  const base = homeBase(values.home);
  const dryRun = values['dry-run'] === true;

  let overrideDays: number | undefined;
  if (values.days !== undefined) {
    // Digits only, before `Number()`. `Number` also accepts `1e3`, `0x1e`,
    // surrounding whitespace and `''` (as 0), so without this gate the refusal
    // below would describe a stricter input than the command actually takes.
    const parsed = /^\d+$/.test(values.days) ? Number(values.days) : Number.NaN;
    // Refused rather than clamped: a mistyped horizon silently rounded to
    // something valid would expire a different set of bodies than the one the
    // user asked for, and expiry is not undoable.
    if (!RETAIN_DAYS.safeParse(parsed).success) {
      io.err(
        `aka prune: --days needs a whole number of days, from ${String(RETAIN_DAYS.minValue)} to ${String(RETAIN_DAYS.maxValue)}\n`,
      );
      return;
    }
    overrideDays = parsed;
  }

  const { settings, managed } = readEffectiveSettings(base, managedOverride);
  const retention = settings.bodyRetention;

  // A lock reaches this command, not only the settings WRITE path. `--days`
  // does not persist anything, so it slips past `applyOnboarding`'s
  // `ManagedFieldError` — but it decides what gets destroyed, and it decides it
  // in the worse direction: a shorter window expires strictly MORE than the
  // pinned policy allows, permanently, on a machine whose administrator set
  // that lock to stop exactly this. The refusal is the same argument as the
  // `--days` validation above, applied to who is asking rather than to what
  // they typed.
  if (overrideDays !== undefined && isFieldManaged(managed, 'bodyRetention')) {
    io.err(
      `aka prune: ${managedByLabel(managed)} sets the retention window; --days cannot override it.\n`,
    );
    return;
  }

  if (!retention.enabled && overrideDays === undefined) {
    io.out('Body expiry is off. Turn it on in Settings, or pass --days to run a one-off pass.\n');
    return;
  }

  const days = overrideDays ?? retention.retainDays;
  const now = Date.now();
  const cutoff = now - days * DAY_MS;

  // The decision itself is `syncLaneRetentionOf`'s, not re-derived here. This
  // command and the background sweep each gather its two inputs with their own
  // copy of the same helper, so the two copies must stay identical; both suites
  // pin the same four states (scoped, machine, unparseable credential, read
  // that throws).
  const sweepSyncLane = syncLaneRetentionFor(settings, base);

  const db = openLocalDatabase(dataDir(base));
  const plan = db.bodyRetention.preview({ cutoff, sweepSyncLane });

  if (plan.rowsExpired === 0) {
    io.out(`Nothing to expire older than ${String(days)} days.\n`);
  } else if (dryRun) {
    io.out(
      `Would expire ${String(plan.rowsExpired)} bodies older than ${String(days)} days, freeing ${fmtBytes(plan.bytesFreed)}.\n`,
    );
  } else {
    const out = db.bodyRetention.expire({ cutoff, sweepSyncLane, now });
    io.out(
      `Expired ${String(out.rowsExpired)} bodies older than ${String(days)} days, freeing ${fmtBytes(out.bytesFreed)}.\n`,
    );
    if (!out.done) io.out('More remain — run again to continue.\n');
  }

  // Worded to hold in every state that keeps these rows: attached, carrying
  // half an attachment, or holding a history-sync grant. Only the first is an
  // attachment, so the line claims no connection — only that the rows are
  // unsent and a deployment could still claim them.
  if (plan.rowsHeldBySync > 0) {
    io.out(
      `${String(plan.rowsHeldBySync)} kept: not yet sent, and could still be owed to a deployment.\n`,
    );
  }

  // Said on every path that cleared something, because it is the question a
  // user asks next and the answer is counter-intuitive: SQLite returns the
  // pages to its own freelist, so new captures reuse them and the store stops
  // growing — but the FILE does not shrink on its own.
  if (!dryRun && plan.rowsExpired > 0) {
    io.out('Freed pages are reused by new captures; the file itself does not shrink.\n');
  }
}
