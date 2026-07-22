import { realpathSync, statSync } from 'node:fs';
import { basename, dirname, relative, resolve } from 'node:path';

import type { FileEgressHits } from '@akasecurity/detections';
import { isVendoredPath, resolveEgress } from '@akasecurity/detections';
import type { LocalDatabase } from '@akasecurity/persistence';
import { defaultDataDir, readWorkspaceSettings } from '@akasecurity/persistence';
import { resolveRepoIdentity, resolveWorktreeRoot, toPosix } from '@akasecurity/plugin-sdk';
import type { EgressWriteSummary } from '@akasecurity/schema';

// The egress-recording pass shared by `aka scan` and the web-ui's Scan page:
// take the raw per-file extraction the walk produced, anchor it to a stable
// project identity, and hand it to the store writer.
//
// The walk that produced these hits is complete under the scan target, so the
// write reconciles in 'walk' mode: stored call sites under the walked prefix
// are replaced wholesale. The prefix is the scan target's own path relative to
// the project root — '' for a root scan, 'src' for a subtree, and the file's
// own path for a single-file scan, which is what keeps a one-file scan from
// clearing the rest of the project.
//
// Fail-open like every store write on the scan path: recording egress is a
// side benefit of a scan, so any failure returns null and never breaks the
// scan that triggered it.

/** What one egress-recording pass wrote, for host display (`aka scan`). */
export type EgressRecordResult = EgressWriteSummary & { project: string };

/**
 * Record the egress `scanPathIntoStore` collected for `target`. Returns the
 * project's live totals, or null when the Data Shares kill-switch is off, the
 * target does not exist, or any step fails (fail-open). `base` is the `~/.aka`
 * base the kill-switch is read from. The caller owns the database handle.
 */
export function recordProjectEgress(
  db: LocalDatabase,
  target: string,
  egress: { files: FileEgressHits[] },
  base: string = defaultDataDir(),
): EgressRecordResult | null {
  try {
    if (!readWorkspaceSettings(base).dataSharesInPlace) return null;

    // The identity resolvers walk UP from the target, so they need an absolute
    // path. A nonexistent target must not resolve through its existing
    // ancestors into a repo walk — statSync throws into the catch below.
    const abs = resolve(target);
    const targetDir = statSync(abs).isDirectory() ? abs : dirname(abs);

    const identity = resolveRepoIdentity(abs);
    const worktreeRoot = resolveWorktreeRoot(abs);

    // The root every stored path is relative to, and the key every stored row
    // reconciles on.
    let root: string;
    let projectKey: string;
    let project: string;
    let projectId: string | null;

    if (identity && worktreeRoot) {
      // A linked worktree's identity resolves to its HEAD repo (resolveRepoIdentity),
      // but paths are relativized against worktreeRoot, which is the CURRENT
      // worktree's own root — so a linked-worktree scan shares its head repo's
      // project key while its stored file paths are relative to its own checkout.
      root = worktreeRoot;
      // identity.url is the remote URL, or the worktree root PATH when the repo
      // has no remote. The 'git:' prefix keeps that path-shaped fallback from
      // aliasing the 'path:' key a non-git walk of the same directory produces.
      projectKey = `git:${identity.url}`;
      project = identity.name;
      projectId = db.sourceProject.upsert({
        url: identity.url,
        name: identity.name,
        attributes: {},
      });
    } else {
      root = targetDir;
      // Keyed on the realpath so two symlinked routes to one directory share a
      // key, and so two directories with the same basename never collide.
      // Relativization still uses `root` as the walker saw it.
      const realRoot = realpathSync(targetDir);
      projectKey = `path:${realRoot}`;
      project = basename(realRoot);
      projectId = null;
    }

    const files: FileEgressHits[] = [];
    for (const hit of egress.files) {
      const file = toPosix(relative(root, hit.file));
      // Outside the resolved root: reconciliation is scoped to paths under it,
      // so a row keyed on a '../' path could never be replaced or cleared.
      if (file === '' || file.startsWith('../')) continue;
      // The walk-mode reconciler's delete excludes dot-paths (`file NOT LIKE
      // '.%' AND file NOT LIKE '%/.%'`), on the premise that this walk never
      // descends into dot-directories. That premise does not hold — a
      // root-level dot-file, an `.akaignore` `!` negation, or a directly-named
      // dot-file target can all put one here — so a stored dot-path row would
      // be one no future walk-mode scan could ever clear. Skip it instead: this
      // pipeline simply does not record dot-path egress; the plugin scanner's
      // ledger mode owns those files.
      if (file.startsWith('.') || file.includes('/.')) continue;
      // `vendored` describes the path being stored — an absolute path can pick
      // up a vendor/ segment from an ancestor outside the project entirely.
      files.push({ ...hit, file, vendored: isVendoredPath(file) });
    }

    const summary = db.shares.recordProjectEgress({
      projectKey,
      project,
      projectId,
      reconcile: { mode: 'walk', walkedPrefix: toPosix(relative(root, abs)) },
      hits: resolveEgress(files),
    });
    return { ...summary, project };
  } catch {
    return null;
  }
}
