import { relative } from 'node:path';

import type { FileEgressHits } from '@akasecurity/detections';
import { isVendoredPath, resolveEgress } from '@akasecurity/detections';
import type { LocalDatabase } from '@akasecurity/persistence';
import { defaultDataDir, readWorkspaceSettings } from '@akasecurity/persistence';
import { toPosix } from '@akasecurity/plugin-sdk';
import type { EgressWriteSummary, RecordProjectEgressInput } from '@akasecurity/schema';

import { resolveScanProject } from './scan-project.ts';

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

/**
 * What one egress-recording pass wrote, plus the resolved input it wrote, for a
 * caller that goes on to forward it.
 */
export type EgressRecordResult = EgressWriteSummary & {
  project: string;
  /**
   * The exact input the store consumed: the plaintext prefixed `projectKey`,
   * the resolved hits with their snippets, and the walk-mode reconcile.
   *
   * LOCAL data, and the reason it is returned rather than rebuilt is that
   * resolving it is the expensive half of this pass. A forwarder projects it
   * through `toEgressIngestRequest`, which is what strips the snippets and
   * digests the key; nothing prints, logs or serialises it as it stands.
   */
  input: RecordProjectEgressInput;
};

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

    const scanned = resolveScanProject(target);
    const { root, projectKey } = scanned;
    const project = scanned.name;
    const abs = scanned.target;
    const projectId =
      scanned.repo === undefined
        ? null
        : db.sourceProject.upsert({
            url: scanned.repo.url,
            name: scanned.repo.name,
            attributes: {},
          });

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

    // Built once and handed on: the caller that forwards must send the SAME
    // input the store took, not a second resolution of the same tree.
    const input: RecordProjectEgressInput = {
      projectKey,
      project,
      projectId,
      reconcile: { mode: 'walk', walkedPrefix: toPosix(relative(root, abs)) },
      hits: resolveEgress(files),
    };
    const summary = db.shares.recordProjectEgress(input);
    return { ...summary, project: input.project, input };
  } catch {
    return null;
  }
}
