import { statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { manifestKindOf } from '@akasecurity/detections';
import {
  resolveNonGitProject,
  resolveRepoIdentity,
  resolveWorktreeRoot,
} from '@akasecurity/plugin-sdk';

/** The project a scan of a target belongs to. */
export interface ScanProject {
  /** The absolute scan target. */
  target: string;
  /** The directory every stored path is relative to. */
  root: string;
  /** The key every stored row reconciles on: `git:<identity>` or `path:<dir>`. */
  projectKey: string;
  /** The display name. */
  name: string;
  /** The repository identity, for a target inside a git working tree. */
  repo?: { url: string; name: string } | undefined;
}

/**
 * Resolve the project a scan of `target` belongs to: the git working tree and
 * its remote identity, else the nearest project boundary a dependency manifest
 * marks. Throws when `target` does not exist.
 */
export function resolveScanProject(target: string): ScanProject {
  // The identity resolvers walk UP from the target, so they need an absolute
  // path. A nonexistent target must not resolve through its existing ancestors
  // into a repo walk, so statSync runs first and throws.
  const abs = resolve(target);
  const targetDir = statSync(abs).isDirectory() ? abs : dirname(abs);

  const identity = resolveRepoIdentity(abs);
  const worktreeRoot = resolveWorktreeRoot(abs);
  if (identity && worktreeRoot) {
    // A linked worktree's identity resolves to its HEAD repo, but paths are
    // relative to the current worktree's own root, so a linked-worktree scan
    // shares its head repo's project key. identity.url is the remote URL, or the
    // worktree root path when the repo has no remote; the 'git:' prefix keeps
    // that path-shaped fallback from aliasing the 'path:' key a non-git walk of
    // the same directory produces.
    return {
      target: abs,
      root: worktreeRoot,
      projectKey: `git:${identity.url}`,
      name: identity.name,
      repo: { url: identity.url, name: identity.name },
    };
  }
  // A non-git target anchors on the highest ancestor carrying a dependency
  // manifest, so `/proj` and `/proj/src` key on one project. With no manifest
  // above it, the target itself is the root. `root` and the `path:` key move
  // together, so stored paths always match the key.
  const { root, projectKey, project } = resolveNonGitProject(targetDir, manifestKindOf);
  return { target: abs, root, projectKey, name: project };
}
