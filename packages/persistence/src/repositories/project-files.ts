import { randomUUID } from 'node:crypto';
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { ProjectFilesScan } from '@akasecurity/schema';

import { getRow } from '../internal/rows.ts';

/**
 * Writer for the real project-file inventory (the Inventory page's file tree).
 * One scan replaces the project's tree: every walked file is upserted (existing
 * rows keep their id/created_at and any findings/blocked state the read side
 * layers on), then rows the scan did NOT re-see are deleted — vanished files
 * drop off the tree. The delete keys on an updated_at watermark (every upsert
 * in the same pass stamps `now`), so no `path NOT IN (…)` parameter explosion.
 * A TRUNCATED scan skips the delete: a partial walk must never shrink the tree.
 */
export class SqliteProjectFilesRepository {
  private readonly upsertStmt: StatementSync;
  private readonly pruneStmt: StatementSync;
  private readonly maxStampStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.maxStampStmt = db.prepare(
      'SELECT coalesce(max(updated_at), 0) AS maxStamp FROM project_file WHERE project_id = :projectId',
    );
    this.upsertStmt = db.prepare(
      `INSERT INTO project_file
         (id, project_id, path, name, origin, default_access, findings_count, blocked_at, note, created_at, updated_at)
       VALUES
         (:id, :projectId, :path, :name, :origin, :defaultAccess, 0, NULL, NULL, :now, :now)
       ON CONFLICT (project_id, path) DO UPDATE SET
         name = excluded.name,
         origin = excluded.origin,
         default_access = excluded.default_access,
         updated_at = excluded.updated_at`,
    );
    this.pruneStmt = db.prepare(
      'DELETE FROM project_file WHERE project_id = :projectId AND updated_at < :now',
    );
  }

  /** Replace `projectId`'s tree with the scan's files. Caller wraps in a transaction. */
  replaceForProject(projectId: string, scan: ProjectFilesScan, now: number): void {
    // The prune keys on `updated_at < stamp`, so the stamp must be STRICTLY
    // newer than every stored row's — two scans inside one clock millisecond
    // would otherwise leave vanished files behind. Monotonic, not wall-clock.
    const maxStamp = getRow<{ maxStamp: number }>(this.maxStampStmt, { projectId })?.maxStamp ?? 0;
    const stamp = Math.max(now, maxStamp + 1);
    for (const file of scan.files) {
      this.upsertStmt.run({
        id: randomUUID(),
        projectId,
        path: file.path,
        name: file.name,
        origin: file.origin,
        defaultAccess: file.defaultAccess,
        now: stamp,
      });
    }
    if (!scan.truncated) this.pruneStmt.run({ projectId, now: stamp });
  }
}
