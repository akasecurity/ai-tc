import { isAbsolute } from 'node:path';

import { gitCommitId } from '@akasecurity/persistence';
import type { AuditEventInput } from '@akasecurity/schema';

import { readHeadCommits, resolveGitBranch } from './repo.ts';

/** A shell command a session ran, as its transcript records it. */
export interface SessionCommand {
  /** The directory the command ran in. */
  readonly cwd: string | undefined;
  /** When the command was issued, as an ISO timestamp. */
  readonly occurredAt: string;
  /** The command text. */
  readonly command: string | undefined;
  /** The scope key the command's rows carry. */
  readonly scopeKey?: string | undefined;
}

/** How long after a git command its commits are attributed to it. */
export const GIT_COMMIT_WINDOW_MS = 15 * 60_000;

const COMMITTING_GIT_COMMAND = /\bgit\b[\s\S]*\b(?:commit|merge|rebase|cherry-pick|am|revert)\b/;

/**
 * One `git_commit` row per commit the checkout reached within `GIT_COMMIT_WINDOW_MS` of a git
 * command that makes commits, for each such command with an absolute working directory. The row
 * is keyed on the session and the commit id, so a commit seen by two commands, or again on a
 * later pass, is one row, stamped with the scope key of the command that first saw it.
 */
export function sessionCommitEvents(
  sessionId: string,
  commands: readonly SessionCommand[],
): AuditEventInput[] {
  const events = new Map<string, AuditEventInput>();
  for (const call of commands) {
    const { cwd, command } = call;
    if (cwd === undefined || !isAbsolute(cwd) || command === undefined) continue;
    if (!COMMITTING_GIT_COMMAND.test(command)) continue;
    const issuedAt = Date.parse(call.occurredAt);
    if (!Number.isFinite(issuedAt)) continue;
    const commits = readHeadCommits(cwd, issuedAt - 1000, issuedAt + GIT_COMMIT_WINDOW_MS);
    if (commits.length === 0) continue;
    const branch = resolveGitBranch(cwd);
    const { scopeKey } = call;
    for (const { commit, at, kind } of commits) {
      const id = gitCommitId(sessionId, commit);
      if (events.has(id)) continue;
      const attributes: Record<string, unknown> = { commit, kind };
      if (branch !== undefined) attributes.branch = branch;
      if (scopeKey !== undefined) attributes.scope_key = scopeKey;
      events.set(id, {
        id,
        eventType: 'git_commit',
        parentId: sessionId,
        rootSessionId: sessionId,
        startedAt: new Date(at).toISOString(),
        attributes,
      });
    }
  }
  return [...events.values()];
}
