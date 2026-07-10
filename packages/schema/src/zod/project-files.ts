import { z } from 'zod';

import { AccessLevel, Origin } from './inventory.ts';

// The real project-file scan contract: what the plugin's SessionStart pass
// walks out of the session's git worktree and hands to persistence to become
// `project_file` rows (the Inventory page's file tree). Plugin-local shapes —
// deliberately NO .meta({ id }): they must not leak into the generated
// OpenAPI components (see the `.meta` id-leak gotcha in local.ts).

/** One walked file, repo-relative with posix separators. */
export const ProjectFileInput = z.object({
  path: z.string().min(1),
  name: z.string().min(1),
  origin: Origin,
  defaultAccess: AccessLevel,
});
export type ProjectFileInput = z.infer<typeof ProjectFileInput>;

/**
 * One scan of a project's working tree. `truncated` marks a walk that hit the
 * file cap — the tree is partial, and the writer must not delete rows beyond
 * what it re-saw. An EMPTY files list never reaches persistence (a failed walk
 * fails open by dropping the scan, not by wiping the previous tree).
 */
export const ProjectFilesScan = z.object({
  files: z.array(ProjectFileInput),
  truncated: z.boolean(),
  scannedAt: z.string(),
});
export type ProjectFilesScan = z.infer<typeof ProjectFilesScan>;
