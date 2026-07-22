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
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { basename, extname, isAbsolute, relative } from 'node:path';

import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type {
  DataGateway,
  FileEgressHits,
  ManifestKind,
  PluginConfig,
  PluginRuntime,
  ScanLedgerEntry,
  ScanLedgerState,
  SourceTool,
} from '@akasecurity/plugin-sdk';
import {
  contentHashOf,
  createPluginRuntime,
  EGRESS_CODE_EXTENSIONS,
  EGRESS_VERSION_MATERIAL,
  extractEgress,
  extractManifestSdks,
  isVendoredPath,
  resolveEgress,
  resolveRepoIdentity,
  resolveWorktreeRoot,
  toPosix,
} from '@akasecurity/plugin-sdk';

import type { DiscoverOptions } from './discover.ts';
import { discoverGitRepos } from './discover.ts';
import { collectManifests } from './manifests.ts';
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

// The ledger fingerprint spans everything that decides what a re-read would
// produce: the detection ruleset, the egress extractor + provider registry, and
// whether egress extraction runs at all. Folding the toggle in matters because
// the ledger keeps advancing while egress is switched off — without it, files
// left untouched during the off period would carry ledger rows that suppress
// the re-read forever, so their egress would never be extracted once it is
// switched back on.
async function loadLedger(
  gateway: DataGateway,
  runtime: PluginRuntime,
  dataSharesInPlace: boolean,
): Promise<LedgerContext> {
  const egressMaterial = `${dataSharesInPlace ? 'egress:on' : 'egress:off'}\n${EGRESS_VERSION_MATERIAL}`;
  const rulesetHash = contentHashOf(
    `${await runtime.rulesetFingerprint()}:${contentHashOf(egressMaterial)}`,
  );
  return { previous: await gateway.scanLedger(rulesetHash), rulesetHash };
}

// The project identity every recorded egress row is keyed and relativized on.
// `root` is the worktree root, not the scan root, so a scan started from a
// subdirectory produces the same stored keys as a scan of the whole repo.
interface EgressProject {
  root: string;
  projectKey: string;
  project: string;
}

// Derived exactly like the CLI/web-ui pipeline's: the two must agree byte for
// byte or one project splits into two rows that never reconcile each other.
// identity.url is the remote URL, or the worktree root PATH when the repo has
// no remote — the 'git:' prefix keeps that path-shaped fallback from aliasing
// the 'path:' key a non-git scan of the same directory produces.
function resolveEgressProject(rootDir: string): EgressProject | null {
  try {
    const identity = resolveRepoIdentity(rootDir);
    const worktreeRoot = resolveWorktreeRoot(rootDir);
    if (identity && worktreeRoot) {
      return { root: worktreeRoot, projectKey: `git:${identity.url}`, project: identity.name };
    }
    // Keyed on the realpath so two symlinked routes to one directory share a
    // key; relativization still uses the directory as the walker saw it.
    const realRoot = realpathSync(rootDir);
    return { root: rootDir, projectKey: `path:${realRoot}`, project: basename(realRoot) };
  } catch {
    return null;
  }
}

// A stored path key, or null when the file sits outside the project root —
// reconciliation is scoped to paths under it, so a '../' key could never be
// replaced or cleared by a later scan.
function egressKey(root: string, absPath: string): string | null {
  const rel = toPosix(relative(root, absPath));
  return rel === '' || rel.startsWith('../') ? null : rel;
}

// Per-run egress accumulator. `scannedFiles` is the reconciliation universe:
// the write replaces exactly these files' stored rows (plus deletions) and
// preserves everything else, so a file must be listed here whenever its content
// was read — including when it produced no hits, which is how a URL that was
// removed from a file gets cleared.
interface EgressAccumulator {
  project: EgressProject;
  files: FileEgressHits[];
  scannedFiles: string[];
  deletedFiles: string[];
}

// Open an accumulator for this scan, or null when the project identity cannot
// be resolved (a root that vanished mid-scan) — egress is a side benefit of a
// scan and never breaks the scan that triggered it.
function startEgress(rootDir: string): EgressAccumulator | null {
  const project = resolveEgressProject(rootDir);
  if (project === null) return null;
  return { project, files: [], scannedFiles: [], deletedFiles: [] };
}

// Extract one just-read file's egress. Code files yield URL/IP hits; manifests
// yield SDK dependencies. Files containing NUL bytes are binary and are skipped.
function collectFileEgress(
  acc: EgressAccumulator,
  absPath: string,
  content: string,
  manifestKind: ManifestKind | null,
): void {
  const file = egressKey(acc.project.root, absPath);
  if (file === null) return;
  acc.scannedFiles.push(file);

  if (content.includes('\u0000')) return;

  const vendored = isVendoredPath(file);
  if (manifestKind !== null) {
    const sdkHits = extractManifestSdks(content, manifestKind);
    if (sdkHits.length > 0) acc.files.push({ file, vendored, endpoints: [], sdkHits });
    return;
  }
  if (!EGRESS_CODE_EXTENSIONS.has(extname(absPath))) return;
  const endpoints = extractEgress(content);
  if (endpoints.length > 0) acc.files.push({ file, vendored, endpoints, sdkHits: [] });
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
// longer exists on disk is resolved with an empty current-keys set. Returns the
// absolute paths it swept, so the egress write can clear their stored rows too.
async function sweepDeletedFiles(
  gateway: DataGateway,
  rootDir: string,
  previous: Map<string, ScanLedgerState>,
): Promise<string[]> {
  const deleted: string[] = [];
  for (const path of previous.keys()) {
    if (!isUnderRoot(path, rootDir) || existsSync(path)) continue;
    deleted.push(path);
    await resolveRemovedFindings(gateway, path, [], { deleted: true });
  }
  return deleted;
}

async function scanDir(
  runtime: PluginRuntime,
  gateway: DataGateway,
  config: PluginConfig,
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

  // The Data Shares kill-switch, read straight off the parsed settings the
  // plugin config already carries. Resolved once, up front, so a disabled
  // toggle skips extraction itself rather than extracting and discarding.
  const egress: EgressAccumulator | null = config.settings.dataSharesInPlace
    ? startEgress(rootDir)
    : null;

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

    // Egress extraction happens HERE, at the read point — past the tier-1/2
    // skips but BEFORE the tier-3 dedup below. A file whose content duplicates
    // an already-seen file still contains this project's egress, so hooking
    // extraction to capture instead would silently drop it.
    if (egress) collectFileEgress(egress, file.path, file.content, null);

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

  // Dependency manifests carry SDK evidence but no source extension, so the
  // source walk never yields them. They are ledgered exactly like walked files
  // and never go through capture — they are egress evidence, not code to scan.
  if (egress) scanManifests(egress, ledger, updates);

  const deleted = await sweepDeletedFiles(gateway, rootDir, ledger.previous);
  if (egress) {
    for (const path of deleted) {
      const key = egressKey(egress.project.root, path);
      if (key !== null) egress.deletedFiles.push(key);
    }
  }

  // Egress commits BEFORE the ledger. If the write fails the ledger batch is
  // skipped entirely, so the next scan re-reads these files and retries;
  // finding capture is idempotent by content hash, so re-running it is free.
  // Advancing the ledger past a failed write would hide the gap forever.
  const committed = await commitEgress(gateway, egress);
  if (committed === null) {
    return { rootDir, scanned, skipped, findings, gitignoredFindings, byRule, bySeverity };
  }

  await gateway.recordScanned(ledgerable(updates, egress, committed));
  return { rootDir, scanned, skipped, findings, gitignoredFindings, byRule, bySeverity };
}

// Ledger + extract every dependency manifest under the project root. Mirrors
// the walked-file tiers: an unchanged mtime skips without reading, and content
// that hashes the same only refreshes the recorded mtime. A manifest that is
// skipped at either tier stays out of `scannedFiles`, so ledger-mode
// reconciliation preserves the rows it already has.
function scanManifests(
  egress: EgressAccumulator,
  ledger: LedgerContext,
  updates: ScanLedgerEntry[],
): void {
  for (const manifest of collectManifests(egress.project.root)) {
    const prev = ledger.previous.get(manifest.path);
    if (prev?.mtime === manifest.mtime) continue;

    let content: string;
    try {
      content = readFileSync(manifest.path, 'utf8');
    } catch {
      continue;
    }

    const hash = contentHashOf(content);
    updates.push({
      path: manifest.path,
      mtime: manifest.mtime,
      contentHash: hash,
      rulesetHash: ledger.rulesetHash,
    });
    if (prev?.contentHash === hash) continue;

    collectFileEgress(egress, manifest.path, content, manifest.kind);
  }
}

// Write the run's egress. Returns null only when the write was attempted and
// failed — the signal to skip this run's ledger commit. A disabled toggle or an
// empty run is a success: nothing to record is not a failure, and freezing the
// ledger on a deliberate skip would re-read the whole tree on every scan.
//
// On success it returns the project-relative files the write declined to
// record (empty in the ordinary case). `projectId` is null because this
// pipeline resolves no source project; the writer treats that as "inherit",
// so passing null keeps whatever link the CLI pipeline already stored.
async function commitEgress(
  gateway: DataGateway,
  egress: EgressAccumulator | null,
): Promise<ReadonlySet<string> | null> {
  if (!egress) return EMPTY_DROPPED;
  const { project, files, scannedFiles, deletedFiles } = egress;
  if (scannedFiles.length === 0 && deletedFiles.length === 0 && files.length === 0) {
    return EMPTY_DROPPED;
  }

  try {
    const summary = await gateway.recordProjectEgress({
      projectKey: project.projectKey,
      project: project.project,
      projectId: null,
      reconcile: { mode: 'ledger', scannedFiles, deletedFiles },
      hits: resolveEgress(files),
    });
    return new Set(summary.droppedFiles);
  } catch {
    return null;
  }
}

const EMPTY_DROPPED: ReadonlySet<string> = new Set<string>();

// Hold back the ledger entries for files whose hits the egress write declined.
// Ledgering a dropped file would tier-1 skip it on every later scan, so its
// egress would never be written at all; withholding the entry costs one re-read
// next scan and lets the project converge across runs.
function ledgerable(
  updates: readonly ScanLedgerEntry[],
  egress: EgressAccumulator | null,
  dropped: ReadonlySet<string>,
): ScanLedgerEntry[] {
  if (!egress || dropped.size === 0) return [...updates];
  return updates.filter((entry) => {
    const key = egressKey(egress.project.root, entry.path);
    return key === null || !dropped.has(key);
  });
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
    const ledger = await loadLedger(gateway, runtime, config.settings.dataSharesInPlace);
    return await scanDir(runtime, gateway, config, seen, ledger, rootDir, opts);
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
    const ledger = await loadLedger(gateway, runtime, config.settings.dataSharesInPlace);
    for (const rootDir of repoDirs) {
      const repoSummary = await scanDir(runtime, gateway, config, seen, ledger, rootDir, opts);
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
