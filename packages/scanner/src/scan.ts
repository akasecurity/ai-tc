// Worktree scanner: walk source files under a root directory and run each
// through the detect→record path the live hooks use. Idempotent two ways:
// findings are deduped by content hash, and a scan-ledger row (path + mtime +
// hash, keyed to the ruleset fingerprint) is kept for EVERY processed file —
// including clean ones, which `persist: 'with-findings'` never records as
// events — so /aka:scan re-runs skip unchanged files without re-reading them.
// Any ruleset change invalidates the ledger, so a new detection rule rescans
// previously-clean files.
//
// scanAllRepos shares one gateway + runtime across all discovered repos so
// deduplication is global — the same file appearing in multiple repos (e.g. a
// vendored copy) is only sent to the detection engine once.
import { existsSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type {
  DataGateway,
  PluginConfig,
  PluginRuntime,
  ScanLedgerEntry,
  ScanLedgerState,
  SourceTool,
} from '@akasecurity/plugin-sdk';
import { contentHashOf, createPluginRuntime } from '@akasecurity/plugin-sdk';

import type { DiscoverOptions } from './discover.ts';
import { discoverGitRepos } from './discover.ts';
import { computeResolutions } from './resolve.ts';
import { type WalkOptions, walkSourceFiles } from './walk.ts';

// The scanner is host-agnostic: the hosting plugin declares which tool the
// findings originate from (required!).
export interface ScanOptions extends WalkOptions {
  sourceTool: SourceTool;
}

// scanAllRepos options: discovery scope + scan options.
export type MultiRepoScanOptions = DiscoverOptions & ScanOptions;

export interface WorktreeScanSummary {
  rootDir: string;
  scanned: number;
  skipped: number;
  findings: number;
  // Of `findings`, how many came from .gitignore'd files — scanned and recorded
  // like any other (their events carry metadata.gitignored), but typically
  // local/generated content, so hosts render them as informational.
  gitignoredFindings: number;
  byRule: Record<string, number>;
  bySeverity: Record<string, number>;
}

export interface MultiRepoScanSummary {
  repos: { rootDir: string; summary: WorktreeScanSummary }[];
  totalScanned: number;
  totalSkipped: number;
  totalFindings: number;
  totalGitignoredFindings: number;
  byRule: Record<string, number>;
  bySeverity: Record<string, number>;
}

// The previously scanned state loaded once per scan (already filtered to the
// current ruleset by the gateway) plus the fingerprint new entries record under.
interface LedgerContext {
  previous: Map<string, ScanLedgerState>;
  rulesetHash: string;
}

async function loadLedger(gateway: DataGateway, runtime: PluginRuntime): Promise<LedgerContext> {
  const rulesetHash = await runtime.rulesetFingerprint();
  return { previous: await gateway.scanLedger(rulesetHash), rulesetHash };
}

// Re-scan resolver: diff a path's previously-open at-rest finding_keys against
// the keys this scan just produced for it (empty for a deleted file), and
// auto-resolve whatever dropped out — a secret that no longer reproduces on
// re-scan is "fixed at source". Rotation (same rule+path, new value) falls out
// of the same diff for free: the old key is absent from `currentKeys` (so it
// resolves) while the new key is a fresh row from the ordinary upsert — no
// special-casing needed here.
//
// Also runs the redetect side (reopenRedetectedFindings): a finding_key that
// is currently produced but whose latest disposition is 'resolved' gets a
// superseding status:'open' row, so a secret that was fixed and then
// re-introduced identically is never silently invisible as "caught".
//
// ATOMICITY NOTE: these resolution writes run AFTER capture()'s own
// transaction, not inside it. A crash between the two can briefly leave a
// re-added secret reading as "caught" under its stale resolved row — the next
// scan re-runs this diff and heals it, and the plugin is fail-open throughout,
// so the window is accepted rather than plumbed into the capture transaction.
async function resolveRemovedFindings(
  gateway: DataGateway,
  path: string,
  currentKeys: string[],
  evidence: Record<string, unknown>,
): Promise<void> {
  const prior = await gateway.openAtRestKeysForPath(path);
  const toResolve = computeResolutions(prior, currentKeys);
  const resolvedAt = Date.now();
  for (const findingKey of toResolve) {
    await gateway.insertResolution({
      findingKey,
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt,
      evidence: JSON.stringify(evidence),
    });
  }

  if (currentKeys.length > 0) {
    await reopenRedetectedFindings(gateway, path, currentKeys, evidence, resolvedAt);
  }
}

// Invariant: a finding_key present in the CURRENT scan is OPEN, regardless of
// past resolutions. A key can be currently produced yet still show up as
// "caught" if its latest disposition is a stale 'resolved' row from an
// earlier fix that has since been undone (the exact same secret re-added at
// the same path) — resolvedAtRestKeysForPath surfaces those. For each one,
// write a superseding status:'open' row so openAtRestKeysForPath /
// severitySummary pick it back up as needing remediation instead of leaving a
// live at-rest secret invisible under a stale "fixed" disposition.
async function reopenRedetectedFindings(
  gateway: DataGateway,
  path: string,
  currentKeys: string[],
  evidence: Record<string, unknown>,
  resolvedAt: number,
): Promise<void> {
  const resolvedKeys = new Set(await gateway.resolvedAtRestKeysForPath(path));
  const toReopen = [...new Set(currentKeys)].filter((key) => resolvedKeys.has(key));
  for (const findingKey of toReopen) {
    await gateway.insertResolution({
      findingKey,
      status: 'open',
      method: 'redetected',
      resolvedAt,
      evidence: JSON.stringify({ ...evidence, reason: 'redetected' }),
    });
  }
}

// True when `path` (absolute) sits under `rootDir` — scopes the deletion sweep
// to the repo currently being scanned, since `ledger.previous` (loaded once)
// may span every repo in a --discover sweep.
function isUnderRoot(path: string, rootDir: string): boolean {
  const rel = relative(rootDir, path);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

// Deleted files never appear in the walk (it only yields files that exist), so
// they need their own sweep: any path this repo previously ledgered that no
// longer exists on disk is resolved with an empty current-keys set.
async function sweepDeletedFiles(
  gateway: DataGateway,
  rootDir: string,
  previous: Map<string, ScanLedgerState>,
): Promise<void> {
  for (const path of previous.keys()) {
    if (!isUnderRoot(path, rootDir) || existsSync(path)) continue;
    await resolveRemovedFindings(gateway, path, [], { deleted: true });
  }
}

async function scanDir(
  runtime: PluginRuntime,
  gateway: DataGateway,
  seen: Set<string>,
  ledger: LedgerContext,
  rootDir: string,
  opts: ScanOptions,
): Promise<WorktreeScanSummary> {
  const byRule: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const updates: ScanLedgerEntry[] = [];
  let scanned = 0;
  let skipped = 0;
  let findings = 0;
  let gitignoredFindings = 0;

  // Tier-1 skip, before the file is even read: same path + mtime as the ledger
  // means unchanged since the last scan under this ruleset. Composed with any
  // caller-supplied shouldRead (which filters silently, without counting).
  const shouldRead = (meta: { path: string; mtime: string; size: number }): boolean => {
    const prev = ledger.previous.get(meta.path);
    if (prev?.mtime === meta.mtime) {
      skipped++;
      return false;
    }
    return true;
  };

  for (const file of walkSourceFiles({
    ...opts,
    rootDir,
    shouldRead: (meta) => (opts.shouldRead?.(meta) ?? true) && shouldRead(meta),
  })) {
    const hash = contentHashOf(file.content);
    const ledgerEntry: ScanLedgerEntry = {
      path: file.path,
      mtime: file.mtime,
      contentHash: hash,
      rulesetHash: ledger.rulesetHash,
    };

    // Tier-2 skip: mtime moved but the content didn't (a touch, a checkout).
    // Refresh the recorded mtime so the next run skips at tier 1.
    const prev = ledger.previous.get(file.path);
    if (prev?.contentHash === hash) {
      skipped++;
      updates.push(ledgerEntry);
      continue;
    }

    // Content-hash dedup across files/repos and previously recorded events.
    // Still ledger the path: identical content means identical (no) findings.
    //
    // EXCEPT when the path still has open at-rest findings. Reaching this tier
    // means the path's content CHANGED (tier 2 didn't match), so those findings
    // may have just been fixed — e.g. deleting a secret leaves the file
    // byte-identical to an already-recorded clean sibling. Skipping here would
    // starve the re-scan resolver (resolveRemovedFindings below never runs for
    // a skipped path) and leave the keys open forever, so fall through to a
    // full capture whose key diff can resolve them.
    if (seen.has(hash) && (await gateway.openAtRestKeysForPath(file.path)).length === 0) {
      skipped++;
      updates.push(ledgerEntry);
      continue;
    }
    seen.add(hash);
    scanned++;

    const result = await runtime.capture(
      {
        kind: 'code_change',
        sourceTool: opts.sourceTool,
        text: file.content,
        occurredAt: file.mtime,
        // Gitignored files are scanned like any other, but the provenance is
        // recorded so policy/dashboards can treat their findings as
        // informational (they are usually local scratch or generated code).
        // `wholeFile` marks this capture as a complete-file snapshot — the
        // signal the re-scan resolver requires before it may treat an absent
        // finding_key as fixed-at-source (hook-captured edit fragments never
        // set it).
        metadata: {
          filePath: file.path,
          wholeFile: true,
          ...(file.gitignored ? { gitignored: true } : {}),
        },
      },
      // 'content-hash': a re-run mints fresh event ids for identical content;
      // the store uses the hash to drop what it already recorded.
      { persist: 'with-findings', dedupe: 'content-hash' },
    );

    for (const finding of result.findings) {
      findings++;
      if (file.gitignored) gitignoredFindings++;
      byRule[finding.ruleId] = (byRule[finding.ruleId] ?? 0) + 1;
      bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    }
    updates.push(ledgerEntry);

    // Re-scan resolver: this file's content changed (it reached capture()),
    // so diff its previously-open at-rest keys against what this scan just
    // produced (result.findingKeys is unset — not [] — when capture()
    // short-circuited on zero findings, which correctly means "nothing
    // currently open here").
    await resolveRemovedFindings(gateway, file.path, result.findingKeys ?? [], {
      contentHash: hash,
    });
  }

  await gateway.recordScanned(updates);
  await sweepDeletedFiles(gateway, rootDir, ledger.previous);
  return { rootDir, scanned, skipped, findings, gitignoredFindings, byRule, bySeverity };
}

export async function scanWorktree(
  config: PluginConfig,
  opts: ScanOptions,
): Promise<WorktreeScanSummary> {
  const rootDir = opts.rootDir ?? process.cwd();
  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  try {
    const seen = await gateway.knownContentHashes();
    const ledger = await loadLedger(gateway, runtime);
    return await scanDir(runtime, gateway, seen, ledger, rootDir, opts);
  } finally {
    await runtime.close();
  }
}

export async function scanAllRepos(
  config: PluginConfig,
  opts: MultiRepoScanOptions,
): Promise<MultiRepoScanSummary> {
  const repoDirs = discoverGitRepos(opts);
  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  const summary: MultiRepoScanSummary = {
    repos: [],
    totalScanned: 0,
    totalSkipped: 0,
    totalFindings: 0,
    totalGitignoredFindings: 0,
    byRule: {},
    bySeverity: {},
  };

  try {
    const seen = await gateway.knownContentHashes();
    // Ledger paths are absolute, so one load covers every repo; scanDir records
    // its updates per repo, so a long --discover sweep keeps partial progress.
    const ledger = await loadLedger(gateway, runtime);
    for (const rootDir of repoDirs) {
      const repoSummary = await scanDir(runtime, gateway, seen, ledger, rootDir, opts);
      summary.repos.push({ rootDir, summary: repoSummary });
      summary.totalScanned += repoSummary.scanned;
      summary.totalSkipped += repoSummary.skipped;
      summary.totalFindings += repoSummary.findings;
      summary.totalGitignoredFindings += repoSummary.gitignoredFindings;
      for (const [rule, count] of Object.entries(repoSummary.byRule)) {
        summary.byRule[rule] = (summary.byRule[rule] ?? 0) + count;
      }
      for (const [sev, count] of Object.entries(repoSummary.bySeverity)) {
        summary.bySeverity[sev] = (summary.bySeverity[sev] ?? 0) + count;
      }
    }
  } finally {
    await runtime.close();
  }

  return summary;
}
