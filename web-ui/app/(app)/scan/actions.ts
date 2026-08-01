'use server';

import { readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, sep } from 'node:path';

import {
  createGuardedFileScanner,
  type DroppedRules,
  recordProjectEgress,
  recordProjectInventory,
  scanPathIntoStore,
  type ScanPathResult,
} from '@akasecurity/local-ops';
import { dataDir } from '@akasecurity/persistence';
import type { EgressWriteSummary } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';
import { scanWorkerUrl } from '../../lib/scan-worker';

// The web twin of `aka scan [path]` — the shared pipeline walks the path and
// records redacted events + masked findings into the local store. No shell is
// involved (pure fs walk), so the path is data, not a command; reading an
// arbitrary local path IS the feature, exactly as the CLI.
//
// Unlike the CLI, this runs the INSTALLED-PACK snapshot, which carries pulled
// and custom packs — regex nothing in this repository has reviewed. A regex has
// no upper bound and `scan()` is synchronous, so one catastrophic pattern would
// not slow this request down, it would stop it answering: a Server Action has
// no harness timeout to be killed by. So the ruleset goes through
// createGuardedFileScanner, which measures each unreviewed rule where it can be
// killed and then runs the scan itself under a wall-clock bound on a worker
// thread. A machine with no pulled or custom regex rule — the overwhelming
// majority — starts no thread and pays nothing.

export interface ScanResult {
  ok: boolean;
  scanned?: number;
  findings?: number;
  egress?: EgressWriteSummary;
  error?: string;
  // Rules the ReDoS guard excluded from this scan, when there were any. The
  // scan is otherwise complete, so this rides alongside the counts rather than
  // replacing them — but it means the ruleset that ran was smaller than the one
  // the Detections page lists, which the user has to be told.
  droppedRules?: string;
}

// One sentence naming what the guard removed and why, or undefined when it
// removed nothing. Both causes are worth distinguishing: rules dropped BEFORE
// the walk were never run at all, while a bound that fired mid-walk means the
// files already scanned saw a bigger ruleset than the ones after it.
function describeDropped(dropped: DroppedRules): string | undefined {
  const parts: string[] = [];
  if (dropped.preflight > 0) {
    parts.push(
      `${String(dropped.preflight)} rule${dropped.preflight === 1 ? '' : 's'} could not be ` +
        `verified as safe to run and ${dropped.preflight === 1 ? 'was' : 'were'} skipped`,
    );
  }
  if (dropped.bound > 0) {
    parts.push(
      `${String(dropped.bound)} rule${dropped.bound === 1 ? '' : 's'} had to be dropped ` +
        `part-way through after a scan overran its time bound`,
    );
  }
  if (parts.length === 0) return undefined;
  // "Everything else in your enabled packs still ran" is true by construction —
  // the guard drops rules, never the scan. It deliberately does not claim the
  // BUILT-IN packs still ran: a user who enabled only a custom pack has no
  // built-ins to fall back on, and a reassurance that is false for them is
  // worse than none.
  return (
    `${parts.join('; ')}. Everything else in your enabled packs still ran. ` +
    'Run `aka detections` to see what is quarantined.'
  );
}

export async function runScan(path: string): Promise<ScanResult> {
  const target = path.trim();
  if (target === '') return { ok: false, error: 'Enter a file or directory path.' };
  try {
    statSync(target);
  } catch {
    return { ok: false, error: `No such file or directory: ${target}` };
  }

  // The installed snapshot is the scan authority — the validated
  // enabled ruleset from the DB, passed explicitly (the engine's process-global
  // registry stays untouched in this long-lived server). An empty ruleset
  // (no packs installed/enabled) still walks the target: egress extraction
  // does not depend on detection rules, so the no-packs guidance below is
  // surfaced after recording rather than skipping the walk.
  const ruleset = db().installedPacks.installedRuleset();
  const noPacksError =
    ruleset.rules.length === 0
      ? ruleset.installedPacks === 0
        ? 'No detection packs installed — run `aka init` first.'
        : ruleset.enabledPacks === 0
          ? 'Every detection pack is disabled — enable one on the Detections page.'
          : 'The installed rule snapshot is unusable — reinstall with `aka init`.'
      : undefined;

  // Built per REQUEST, not per process. The first hang retires isolation for
  // the scanner's whole life, and this server outlives every scan it runs — a
  // process-wide scanner would mean one bad rule cost the dashboard its pulled
  // packs until someone restarted it. Per request, the cost of that recovery is
  // one scan, and the culprit is quarantined in the shared verdict cache so it
  // does not come back. The measurements are cached in the store too (the same
  // table the hooks use), so a second scan re-measures nothing.
  const guard = await createGuardedFileScanner(db(), ruleset.rules, {
    workerUrl: scanWorkerUrl(),
  });
  let result: ScanPathResult;
  try {
    result = await scanPathIntoStore(db(), target, {
      // `scanText`, not `rules`: the guarded scanner already holds the ruleset,
      // and passing it here as well would name the unbounded in-process path.
      scanText: guard.scanText,
      // Per-pack policy actions from the same snapshot, so at-rest findings carry the
      // detection's assigned Monitor/Warn/Redact/Block (not the per-category default).
      ruleActions: ruleset.ruleActions,
      sourceTool: 'cli',
      // Same ~/.aka/data directory as db()'s store, so a finding's finding_key
      // uses the plugin's keyed-HMAC fingerprint and reconciles onto the same
      // row on re-scan instead of duplicating (see scanPathIntoStore).
      dataDir: dataDir(),
    });
  } finally {
    await guard.close();
  }
  const droppedRules = describeDropped(guard.dropped());
  // Keep the Inventory page's project + file tree fresh for the repo just
  // scanned (fail-open, no-op outside a git repo).
  recordProjectInventory(db(), target);
  // Record the destinations/endpoints/call sites the walk extracted into the
  // Data Shares store (fail-open; null when the toggle is off, the target has
  // no resolvable project, or the write failed).
  const egress = recordProjectEgress(db(), target, result.egress);
  revalidatePath('/findings');
  revalidatePath('/security');
  revalidatePath('/inventory');
  revalidatePath('/data-shares');

  // The walk and the egress write already ran — egress extraction does not
  // depend on the ruleset — so the recorded destinations ride along with the
  // pack-state error rather than being dropped.
  if (noPacksError !== undefined)
    return { ok: false, error: noPacksError, egress: egress ?? undefined, droppedRules };

  return {
    ok: true,
    scanned: result.scanned,
    findings: result.findings,
    egress: egress ?? undefined,
    droppedRules,
  };
}

export interface DirEntry {
  name: string;
  path: string;
}

export interface ListDirResult {
  ok: boolean;
  path?: string;
  // Breadcrumb trail from the filesystem root down to `path`, built with
  // node:path so the client never parses/reconstructs paths itself (that
  // broke on Windows, where separators are '\' and roots look like 'C:\').
  crumbs?: DirEntry[];
  // Path to navigate "up" to, or null if `path` is already the root.
  parent?: string | null;
  entries?: DirEntry[];
  error?: string;
}

// Folder picker for the Browse panel — lists subdirectories only (this is a
// scan-target picker, not a file browser). Read-only; the user must click
// "Allow" client-side before the first call, so this itself does no consent
// gating.
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function listDirectory(path?: string): Promise<ListDirResult> {
  const target = path?.trim() ? path.trim() : homedir();
  let entries: DirEntry[];
  try {
    entries = readdirSync(target, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith('.') && e.name !== 'node_modules')
      .map((e) => ({ name: e.name, path: join(target, e.name) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    return { ok: false, error: `Cannot list directory: ${target}` };
  }

  const crumbs: DirEntry[] = [];
  let cursor = target;
  for (;;) {
    const parentOfCursor = dirname(cursor);
    const name = basename(cursor) || cursor.replace(new RegExp(`\\${sep}+$`), '') || cursor;
    crumbs.unshift({ name, path: cursor });
    if (parentOfCursor === cursor) break;
    cursor = parentOfCursor;
  }
  const parent = dirname(target) === target ? null : dirname(target);

  return { ok: true, path: target, crumbs, parent, entries };
}
