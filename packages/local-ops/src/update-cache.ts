import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { dataDir } from '@akasecurity/persistence';
import type { UpdateCache } from '@akasecurity/schema';

import { gatherReportLive, isRecord } from './updates.ts';

// Passive-notice cache: a small JSON file next to the local store so a command can
// print "you're behind" from the last check instantly, and refresh in the background
// for next time. Kept separate from ./updates.ts because it depends on the layout
// helper in @akasecurity/persistence — the report-gathering logic stays free of that
// so it's cheaply unit-testable. The cache shape lives in @akasecurity/schema.

// How long a cached update check stays fresh before the passive notice triggers a
// background refresh. One check per day is plenty and keeps `npm view` off the hot
// path of every command.
export const CHECK_TTL_MS = 24 * 60 * 60 * 1000;

export function cachePath(home: string): string {
  return join(dataDir(home), 'update-check.json');
}

export function readCache(home: string): UpdateCache | null {
  const path = cachePath(home);
  if (!existsSync(path)) return null;
  try {
    const raw: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!isRecord(raw) || typeof raw.checkedAt !== 'number' || !isRecord(raw.report)) return null;
    return raw as unknown as UpdateCache;
  } catch {
    return null;
  }
}

// Persist the cache, but never provision ~/.aka — if the local store dir doesn't
// exist the user hasn't run `aka init`, and a passive check must not create it.
export function writeCache(home: string, cache: UpdateCache): void {
  if (!existsSync(dataDir(home))) return;
  try {
    writeFileSync(cachePath(home), `${JSON.stringify(cache, null, 2)}\n`);
  } catch {
    // best-effort — a failed cache write must never break a command
  }
}

export function isStale(cache: UpdateCache, ttlMs: number = CHECK_TTL_MS): boolean {
  return Date.now() - cache.checkedAt >= ttlMs;
}

// Drop the cache so the next command recomputes from scratch. Called right after an
// `aka update` applies changes: the still-running process reflects the OLD versions,
// so a cache written now would falsely re-nag "update available" until the new
// binary runs.
export function clearCache(home: string): void {
  try {
    rmSync(cachePath(home), { force: true });
  } catch {
    // best-effort
  }
}

// The hidden `__update-refresh` command body: recompute the report and persist it,
// preserving which new-plugin notices were already shown. Silent by design.
export function refreshCache(home: string): void {
  const previous = readCache(home);
  writeCache(home, {
    checkedAt: Date.now(),
    report: gatherReportLive(),
    notifiedPluginIds: previous?.notifiedPluginIds ?? [],
  });
}

// Fire a detached `aka __update-refresh --home <home>` that outlives this process,
// so the NEXT command sees a fresh cache. Zero latency on the current command.
function triggerBackgroundRefresh(home: string): void {
  const entry = process.argv[1];
  if (!entry) return;
  try {
    spawn(process.execPath, [entry, '__update-refresh', '--home', home], {
      detached: true,
      stdio: 'ignore',
    }).unref();
  } catch {
    // no-op — refresh is best-effort
  }
}

// Print the passive "updates available" notice from the cached report, and kick off
// a background refresh when the cache is stale. Suppressed when stdout isn't a TTY
// (pipes / CI) so it never pollutes machine-readable output. Fail-open throughout.
export function notifyFromCache(home: string, opts: { isTty: boolean }): void {
  if (!opts.isTty) return;
  const cache = readCache(home);

  if (cache) {
    const lines: string[] = [];
    for (const s of cache.report.statuses) {
      if (!s.updateAvailable || !s.latest) continue;
      const cmd = s.kind === 'cli' ? 'aka update' : `aka update ${s.id}`;
      lines.push(`  ⬆ ${s.name}: ${s.installed ?? '—'} → ${s.latest} available. Run \`${cmd}\`.`);
    }
    const alreadyShown = new Set(cache.notifiedPluginIds);
    const freshlyShown: string[] = [];
    for (const p of cache.report.availablePlugins) {
      if (alreadyShown.has(p.id)) continue;
      lines.push(
        `  ✨ New plugin available: ${p.name}. Install with \`aka plugins install ${p.id}\`.`,
      );
      freshlyShown.push(p.id);
    }
    if (lines.length > 0) {
      process.stderr.write(`\n${lines.join('\n')}\n`);
    }
    // Record new-plugin notices so they show once, not on every command.
    if (freshlyShown.length > 0) {
      writeCache(home, {
        ...cache,
        notifiedPluginIds: [...cache.notifiedPluginIds, ...freshlyShown],
      });
    }
  }

  if (!cache || isStale(cache)) triggerBackgroundRefresh(home);
}
