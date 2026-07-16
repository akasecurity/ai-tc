import { statSync } from 'node:fs';
import { resolve } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import {
  resolveHeadRoot,
  resolveProjectFiles,
  resolveRepoIdentity,
  resolveWorktreeRoot,
} from '@akasecurity/plugin-sdk';

// The project-inventory pass shared by `aka scan` and the web-ui's Scan page:
// resolve the git repo containing the scan target, upsert its source_project
// row, and record the worktree's file tree — the same pass the Claude Code
// plugin runs at SessionStart, so a repo that is only ever scanned (never
// opened in a live session) still shows up on the Inventory page with a real
// file count instead of an empty pane.
//
// Fail-open like every store write on the scan path: recording inventory is a
// side benefit of a scan, so any failure here returns null and never breaks
// the scan that triggered it.

// What one project-inventory pass recorded, for host display (`aka scan`'s
// summary line and json payload).
export interface ProjectInventoryResult {
  projectId: string;
  name: string;
  url: string;
  fileCount: number;
  // The walk was partial (unreadable subtree, file cap, linked worktree) — the
  // stored tree was extended but not pruned.
  truncated: boolean;
}

/**
 * Upsert the source_project row for the repo containing `target` and record
 * its worktree file tree. Returns what was recorded, or null when `target` is
 * not inside a git repo (nothing is written) or on any error (fail-open).
 * The caller owns the database handle.
 */
export function recordProjectInventory(
  db: LocalDatabase,
  target: string,
): ProjectInventoryResult | null {
  try {
    // findGitRoot walks UP from the target, so it needs an absolute path (a
    // relative one would bottom out at '.'). A file target resolves through
    // its containing directory on the same upward walk.
    const abs = resolve(target);
    // A nonexistent target must not resolve through its (existing) ancestors
    // into a full repo walk — a mistyped path records nothing. Throws into the
    // fail-open catch below.
    statSync(abs);
    const identity = resolveRepoIdentity(abs);
    if (!identity) return null;

    // The project row alone — the host/harness/user dimensions belong to the
    // session passes that actually resolve them (a project-only ensureInventory
    // would re-write user/local with no host link).
    const sourceProjectId = db.sourceProject.upsert({
      url: identity.url,
      name: identity.name,
      attributes: {},
    });

    // undefined means the walk found nothing (or couldn't start) — the project
    // row above still stands, and the stored tree is left untouched.
    const scan = resolveProjectFiles(abs);
    if (scan) db.recordProjectFiles(sourceProjectId, scan);

    // Self-heal ghost projects the pre-worktree-fix resolver minted for
    // checkout paths — the same sweep SessionStart runs, so a repo that is
    // only ever scanned folds its ghosts into the canonical row too.
    const headRoot = resolveHeadRoot(abs);
    const worktreeRoot = resolveWorktreeRoot(abs);
    if (headRoot && worktreeRoot) {
      db.reconcileWorktreeProjects(sourceProjectId, headRoot, worktreeRoot);
    }

    return {
      projectId: sourceProjectId,
      name: identity.name,
      url: identity.url,
      fileCount: scan?.files.length ?? 0,
      truncated: scan?.truncated ?? false,
    };
  } catch {
    return null;
  }
}
