import { parseArgs } from 'node:util';

import { dataDir, openLocalDatabase, readEffectiveSettings } from '@akasecurity/persistence';
import { canSweepSyncLane } from '@akasecurity/schema';

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

export function runPrune(argv: string[], io: Prompter = terminalPrompter()): void {
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
    const parsed = Number(values.days);
    // Refused rather than clamped: a mistyped horizon silently rounded to
    // something valid would expire a different set of bodies than the one the
    // user asked for, and expiry is not undoable.
    if (!Number.isInteger(parsed) || parsed < 1) {
      io.err('aka prune: --days needs a whole number of days, 1 or more\n');
      return;
    }
    overrideDays = parsed;
  }

  const { settings } = readEffectiveSettings(base);
  const retention = settings.bodyRetention;
  if (!retention.enabled && overrideDays === undefined) {
    io.out('Body expiry is off. Turn it on in Settings, or pass --days to run a one-off pass.\n');
    return;
  }

  const days = overrideDays ?? retention.retainDays;
  const now = Date.now();
  const cutoff = now - days * DAY_MS;

  // Asked of the shared predicate rather than re-derived here: this command and
  // the background sweep must never disagree about which bodies are still owed
  // to a deployment, and two copies of that rule would be two answers.
  const sweepSyncLane = canSweepSyncLane(settings);

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

  if (plan.rowsHeldBySync > 0) {
    io.out(
      `${String(plan.rowsHeldBySync)} kept: not yet sent to the control plane this machine is attached to.\n`,
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
