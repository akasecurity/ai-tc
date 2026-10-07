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
import { existsSync, readFileSync } from 'node:fs';
import { dirname, extname, isAbsolute, relative } from 'node:path';

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
  manifestKindOf,
  resolveEgress,
  resolveNonGitProject,
  resolveRepoIdentity,
  resolveWorktreeRoot,
  toPosix,
} from '@akasecurity/plugin-sdk';

import type { DiscoverOptions } from './discover.ts';
import { discoverGitRepos } from './discover.ts';
import { collectManifests } from './manifests.ts';
import { computeResolutions } from './resolve.ts';
import { type ScopeKeyLookup, scopeKeysUnder } from './scope-key.ts';
import { type WalkOptions, walkSourceFiles } from './walk.ts';

// The scanner is host-agnostic: the hosting plugin declares which tool the
// findings originate from (required!).
//
// Without `onRepositoryRoot`: a scan listens for the repositories nested in its
// root itself (see scanDir), so the walk's own option is not one a host sets.
export interface ScanOptions extends Omit<WalkOptions, 'onRepositoryRoot'> {
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
// current ruleset by the gateway), every ledgered path whatever its ruleset
// (what the deletion sweep checks), and the fingerprint new entries record under.
interface LedgerContext {
  previous: Map<string, ScanLedgerState>;
  paths: string[];
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
  return {
    previous: await gateway.scanLedger(rulesetHash),
    paths: await gateway.scanLedgerPaths(),
    rulesetHash,
  };
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
// the 'path:' key a non-git scan of the same directory produces. The non-git
// branch uses the same shared resolver as the CLI/web-ui pipeline, so both key
// and relativize a subtree scan on the same project boundary.
function resolveEgressProject(rootDir: string): EgressProject | null {
  try {
    const identity = resolveRepoIdentity(rootDir);
    const worktreeRoot = resolveWorktreeRoot(rootDir);
    if (identity && worktreeRoot) {
      return { root: worktreeRoot, projectKey: `git:${identity.url}`, project: identity.name };
    }
    // A non-git scan anchors on the nearest project boundary (highest ancestor
    // carrying a dependency manifest), so a subtree scan and a root scan resolve
    // to one project; with no manifest above the target the target itself is the
    // root and different-depth scans cannot reconcile — no boundary to find.
    return resolveNonGitProject(rootDir, manifestKindOf);
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
  // The absolute path of each entry of `deletedFiles`, in the same order. The
  // register's keys are relative to the project root; which repository a deleted
  // path was in is read off the disk, from its absolute path (see commitEgress).
  deletedPaths: string[];
  // Every directory below the scan root that the source walk or the manifest
  // walk listed and that holds a `.git` entry (a nested clone, a submodule, a
  // linked worktree), as a posix path relative to the scan root. A directory
  // both walks listed appears twice. The walks fold such a repository's files
  // into THIS project's register, so its scope key travels beside the register
  // to the gateway (see commitEgress).
  nestedRoots: string[];
}

// Open an accumulator for this scan, or null when the project identity cannot
// be resolved (a root that vanished mid-scan) — egress is a side benefit of a
// scan and never breaks the scan that triggered it.
function startEgress(rootDir: string): EgressAccumulator | null {
  const project = resolveEgressProject(rootDir);
  if (project === null) return null;
  return {
    project,
    files: [],
    scannedFiles: [],
    deletedFiles: [],
    deletedPaths: [],
    nestedRoots: [],
  };
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
// to the repo currently being scanned, since `ledger.paths` (loaded once) may
// span every repo in a --discover sweep.
function isUnderRoot(path: string, rootDir: string): boolean {
  const rel = relative(rootDir, path);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

// Deleted files never appear in the walk (it only yields files that exist), so
// they need their own sweep: any path this repo previously ledgered that no
// longer exists on disk is resolved with an empty current-keys set. The sweep
// reads every ledgered path, not only the current ruleset's: a file deleted
// just before a ruleset change keeps its row under the old hash. Returns the
// absolute paths it swept, so the egress write can clear their stored rows too.
async function sweepDeletedFiles(
  gateway: DataGateway,
  rootDir: string,
  paths: string[],
): Promise<string[]> {
  const deleted: string[] = [];
  for (const path of paths) {
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

  // The scope key lookups for this root (./scope-key.ts). One per call, so what
  // it remembers belongs to this root alone, and it reads nothing until it is
  // asked. It feeds three things: the key stamped on each file that reaches
  // capture (called as `scopeKeyOf(path)`, which climbs to the repository
  // holding the file), the keys of the repositories nested in this root, which a
  // gateway reads beside the register (`scopeKeyOf.ofRepositoryRoot`, see
  // commitEgress), and the key of each path the register lists as deleted, which
  // it reads the same way.
  const scopeKeyOf = scopeKeysUnder(rootDir);

  // Told every directory below the root, by either walk, that holds a `.git`
  // entry: ONE collector, passed to the source walk below and to the manifest
  // walk (scanManifests). The two can list different directories. The manifest
  // walk takes none of the host's excludePatterns, so it lists directories
  // those patterns narrow away; the source walk takes them, and a `!` negation
  // among them can send it into a directory the manifest walk skips. The nested
  // roots are the union, whatever the host's patterns. A directory both walks
  // listed is collected twice and de-duplicated when its key is built. With no
  // register the source walk is given no callback at all and the manifest walk
  // does not run, so a scan with Data Shares off walks exactly as it did before.
  const noteNestedRoot = (relativeDir: string): void => {
    egress?.nestedRoots.push(relativeDir);
  };

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
    onRepositoryRoot: egress === null ? undefined : noteNestedRoot,
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

    // The file's nearest repository decides its key, not this scan root: a
    // nested clone or submodule keys by its own remote, and a nested repository
    // with no remote gets none.
    const scopeKey = scopeKeyOf(file.relativePath);
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
        // Beside the event, never in its metadata: EventMetadata is a published
        // wire shape, and only the local writer stores the key.
        ...(scopeKey !== undefined ? { scopeKey } : {}),
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
  if (egress) scanManifests(egress, ledger, updates, rootDir, noteNestedRoot);

  const deleted = await sweepDeletedFiles(gateway, rootDir, ledger.paths);
  if (egress) {
    for (const path of deleted) {
      const key = egressKey(egress.project.root, path);
      if (key === null) continue;
      egress.deletedFiles.push(key);
      egress.deletedPaths.push(path);
    }
  }

  // Egress commits BEFORE the ledger. If the write fails the ledger batch is
  // skipped entirely, so the next scan re-reads these files and retries;
  // finding capture is idempotent by content hash, so re-running it is free.
  // Advancing the ledger past a failed write would hide the gap forever.
  const committed = await commitEgress(gateway, egress, rootDir, scopeKeyOf);
  if (committed === null) {
    return { rootDir, scanned, skipped, findings, gitignoredFindings, byRule, bySeverity };
  }

  // Same reasoning, for a different loss. `ledger.rulesetHash` was computed
  // before the walk, from the FULL ruleset; if a scan lost its worker partway
  // through, everything after that point was scanned without the pulled/custom
  // rules. Writing those rows would key a partial scan under the full ruleset's
  // hash, and the next run would skip exactly the files the dropped rules never
  // saw. Skipping the batch costs a re-read; writing it hides the gap.
  if (runtime.scanIsolationDegraded()) {
    return { rootDir, scanned, skipped, findings, gitignoredFindings, byRule, bySeverity };
  }

  await gateway.recordScanned(ledgerable(updates, egress, committed));
  return { rootDir, scanned, skipped, findings, gitignoredFindings, byRule, bySeverity };
}

// Ledger + extract every dependency manifest under the SCAN root — the same
// universe the source walk and the deletion sweep cover, so a subtree scan
// never ledgers or reconciles a manifest that its own sweep could not later
// clear. Keys still derive from the project root, so a subtree scan's manifest
// rows reconcile against a whole-repo scan's. Mirrors the walked-file tiers: an
// unchanged mtime skips without reading, and content that hashes the same only
// refreshes the recorded mtime. A manifest that is skipped at either tier stays
// out of `scannedFiles`, so ledger-mode reconciliation preserves the rows it
// already has.
function scanManifests(
  egress: EgressAccumulator,
  ledger: LedgerContext,
  updates: ScanLedgerEntry[],
  rootDir: string,
  onRepositoryRoot: (relativeDir: string) => void,
): void {
  // This walk lists directories whether or not anything under them changed, so a
  // nested repository is reported because the scan passed through it, not
  // because this run happened to re-read one of its files. `onRepositoryRoot` is
  // the collector the source walk reports to as well (see scanDir).
  for (const manifest of collectManifests(rootDir, undefined, onRepositoryRoot)) {
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
//
// Beside the register goes the scope key of every repository nested below the
// scan root that either walk passed through. A gateway that forwards by scope
// sends the register only when each of them may be sent too; the local store
// ignores them. The keys are resolved only when a gateway reads them, so a
// gateway that never asks costs no repository read.
//
// The register's deleted files come from the ledger, not from the walk, so the
// nested roots do not cover them: a clone removed since the last scan, or one an
// ignore file now hides, is in neither walk, and its ledgered paths come back as
// deleted. Beside the register goes the scope key of each deleted path too, read
// off the disk when a gateway asks (see keyOfDeletedPath).
async function commitEgress(
  gateway: DataGateway,
  egress: EgressAccumulator | null,
  rootDir: string,
  scopeKeyOf: ScopeKeyLookup,
): Promise<ReadonlySet<string> | null> {
  if (!egress) return EMPTY_DROPPED;
  const { project, files, scannedFiles, deletedFiles, deletedPaths, nestedRoots } = egress;
  if (scannedFiles.length === 0 && deletedFiles.length === 0 && files.length === 0) {
    return EMPTY_DROPPED;
  }

  // Filled on the first read of `nestedScopeKeys` / `deletedFileKeys` below, and
  // only then.
  let nestedKeys: readonly (string | undefined)[] | undefined;
  let deletedKeys: readonly (string | undefined)[] | undefined;
  try {
    const summary = await gateway.recordProjectEgress(
      {
        projectKey: project.projectKey,
        project: project.project,
        projectId: null,
        reconcile: { mode: 'ledger', scannedFiles, deletedFiles },
        hits: resolveEgress(files),
      },
      {
        // One key per nested root, from this scan's own lookup of a
        // repository ROOT (./scope-key.ts): the directory's own key, found
        // without climbing. A nested directory whose `.git` is a link to
        // nowhere, or is gone by the time a gateway asks, is `undefined` here
        // rather than the key of the repository around it; so is a nested
        // repository with no forge remote. Each root is read fresh, never from
        // the resolver's memory of an earlier answer for that directory. Always
        // a list, even an empty one: a scoped gateway reads a missing list as a
        // register nobody vouched for. The repository lookups it makes do not
        // throw on these inputs, and the gateway reads any throw in this read as
        // local anyway.
        //
        // A getter, memoized: only a gateway that reads the list causes a
        // repository read. The standalone gateway ignores it, and a
        // machine-wide attachment answers before reading it.
        get nestedScopeKeys(): readonly (string | undefined)[] {
          // De-duplicated: a directory both walks listed is one repository.
          nestedKeys ??= [...new Set(nestedRoots)].map((dir) => scopeKeyOf.ofRepositoryRoot(dir));
          return nestedKeys;
        },
        // One key per entry of `reconcile.deletedFiles`, in its order, and
        // memoized like the list above: a gateway reads it at most once.
        deletedFileKeys: () => {
          deletedKeys ??= deletedPaths.map((path) => keyOfDeletedPath(scopeKeyOf, rootDir, path));
          return deletedKeys;
        },
      },
    );
    return new Set(summary.droppedFiles);
  } catch {
    return null;
  }
}

// The scope key of the repository a deleted file was in, read from the disk as
// it is now, or `undefined` when that cannot be proven.
//
// A file whose directory still exists is keyed like a captured file is: by the
// nearest repository above it, climbing from that directory (./scope-key.ts).
// That covers a project file deleted from its own directory, and a file deleted
// from a clone that is still there, whether the walk entered it or not.
//
// A file whose directory is gone has nothing left to climb from. Climbing the
// path alone would stop at the project and answer with ITS key, as though the
// file had been the project's, when the directory may have been a clone that has
// since been removed. So it has no key. The cost is that the stored rows of a
// project directory removed whole are not cleared by this scan.
function keyOfDeletedPath(
  scopeKeyOf: ScopeKeyLookup,
  rootDir: string,
  absPath: string,
): string | undefined {
  if (!existsSync(dirname(absPath))) return undefined;
  return scopeKeyOf(toPosix(relative(rootDir, absPath)));
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
