'use server';

import { readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, sep } from 'node:path';

import {
  recordProjectEgress,
  recordProjectInventory,
  scanPathIntoStore,
} from '@akasecurity/local-ops';
import type { EgressWriteSummary } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// The web twin of `aka scan [path]` — the shared pipeline walks the path and
// records redacted events + masked findings into the local store. No shell is
// involved (pure fs walk), so the path is data, not a command; reading an
// arbitrary local path IS the feature, exactly as the CLI.

export interface ScanResult {
  ok: boolean;
  scanned?: number;
  findings?: number;
  egress?: EgressWriteSummary;
  error?: string;
}

// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
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

  const result = scanPathIntoStore(db(), target, {
    rules: ruleset.rules,
    // Per-pack policy actions from the same snapshot, so at-rest findings carry the
    // detection's assigned Monitor/Warn/Redact/Block (not the per-category default).
    ruleActions: ruleset.ruleActions,
    sourceTool: 'cli',
  });
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

  if (noPacksError !== undefined) return { ok: false, error: noPacksError };

  return {
    ok: true,
    scanned: result.scanned,
    findings: result.findings,
    egress: egress ?? undefined,
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
