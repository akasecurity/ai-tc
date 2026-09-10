'use server';

import { readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, sep } from 'node:path';

import {
  createGuardedFileScanner,
  forwardProjectEgress,
  recordProjectEgress,
  recordProjectInventory,
  scanPathIntoStore,
  type ScanPathResult,
  type SharesForwardOutcome,
} from '@akasecurity/local-ops';
import { dataDir, defaultDataDir } from '@akasecurity/persistence';
import { createSharesSender } from '@akasecurity/remote';
import { type EgressWriteSummary, SOURCE_TOOL } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';
import { describeDropped } from '../../lib/dropped-rules';
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
//
// On an attached machine the register this scan writes is also forwarded to the
// deployment this home's settings name, after the local write. What crosses is
// the same projection the plugin's own scanner sends — destination hosts,
// endpoints and file/line call sites, with no source text and the project key
// replaced by a digest. It can fail every way a network call can, and none of
// them change the scan's result: the walk is already on disk by then, and the
// outcome is reported to the person who clicked Scan rather than swallowed.

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
  // Where the register went, on a machine that is attached. Absent on one that
  // is not, and on a scan that recorded no register to forward — the page then
  // renders exactly what it always did.
  forward?: SharesForwardOutcome;
}

// A Server Action's result is serialised to the browser, and the recorder hands
// back the resolved input it wrote beside the totals: every call site's source
// line, and the project key in plaintext. Declaring the field as the summary
// type drops neither — the serialiser walks the runtime object — so the totals
// are picked by name and the local half never leaves the server.
function summaryOf(recorded: EgressWriteSummary): EgressWriteSummary {
  return {
    destinations: recorded.destinations,
    endpoints: recorded.endpoints,
    callSites: recorded.callSites,
    truncated: recorded.truncated,
    droppedFiles: recorded.droppedFiles,
  };
}

/**
 * Walk `path`, record what it found, and — on an attached machine — forward the
 * register it just recorded unless `options.forward` is false, which is the
 * Scan page's own checkbox saying "keep this one local".
 */
export async function runScan(
  path: string,
  options: { forward?: boolean } = {},
): Promise<ScanResult> {
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
      sourceTool: SOURCE_TOOL.Cli,
      // Same ~/.aka/data directory as db()'s store, so a finding's finding_key
      // uses the plugin's keyed-HMAC fingerprint and reconciles onto the same
      // row on re-scan instead of duplicating (see scanPathIntoStore).
      dataDir: dataDir(),
    });
  } finally {
    await guard.close();
  }
  // Read the quarantine count AFTER the walk, never before: the hard bound
  // quarantines its culprit mid-scan, so a count taken earlier would miss the
  // one row this scan itself produced. It is what `aka detections` prints from,
  // so pointing there is only ever offered when it has something to show.
  const droppedRules = describeDropped(guard.dropped(), db().ruleProbeCache.countQuarantined() > 0);
  // Keep the Inventory page's project + file tree fresh for the repo just
  // scanned (fail-open, no-op outside a git repo).
  recordProjectInventory(db(), target);
  // Record the destinations/endpoints/call sites the walk extracted into the
  // Data Shares store (fail-open; null when the toggle is off, the target has
  // no resolvable project, or the write failed).
  const egress = recordProjectEgress(db(), target, result.egress);

  // After the local write, and in its own catch: the value of a scan is what is
  // already on disk, and nothing here may cost the caller its counts. The state
  // machine is documented never to throw — this guards the action's result
  // against the day that stops being true, not the outcome.
  let forward: SharesForwardOutcome | undefined;
  if (egress) {
    try {
      // Awaited inside this one action, so on an attached machine whose
      // deployment is down the click waits up to the send's deadline before the
      // counts appear. A second, client-started action would remove that wait
      // at the cost of a two-call shape and a page rendering counts it has not
      // finished reporting on; the one-call shape is kept deliberately.
      const outcome = await forwardProjectEgress(defaultDataDir(), egress.input, {
        send: createSharesSender(),
        enabled: options.forward !== false,
      });
      // A machine attached to nothing has nothing to report about, and the field
      // stays absent rather than carrying a status: that keeps what a standalone
      // install's page receives exactly what it received before this action
      // could forward anything at all.
      if (outcome.status !== 'not-attached') forward = outcome;
    } catch {
      forward = undefined;
    }
  }

  revalidatePath('/findings');
  revalidatePath('/security');
  revalidatePath('/inventory');
  revalidatePath('/data-shares');

  // The walk and the egress write already ran — egress extraction does not
  // depend on the ruleset — so the recorded destinations ride along with the
  // pack-state error rather than being dropped.
  if (noPacksError !== undefined)
    return {
      ok: false,
      error: noPacksError,
      egress: egress ? summaryOf(egress) : undefined,
      droppedRules,
      forward,
    };

  return {
    ok: true,
    scanned: result.scanned,
    findings: result.findings,
    egress: egress ? summaryOf(egress) : undefined,
    droppedRules,
    forward,
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
