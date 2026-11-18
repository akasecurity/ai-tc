import { isAbsolute, resolve } from 'node:path';

import { gitCommitId } from '@akasecurity/persistence';
import type { AuditEventInput, GitCommitAttributes } from '@akasecurity/schema';

import type { HeadLog } from './repo.ts';
import { readHeadLog } from './repo.ts';

/** A shell command a session ran, as its transcript records it. */
export interface SessionCommand {
  /** The directory the command ran in. */
  readonly cwd: string | undefined;
  /** When the command was issued, as an ISO timestamp. */
  readonly occurredAt: string;
  /** When its result came back, as an ISO timestamp; undefined until it has. */
  readonly completedAt: string | undefined;
  /** The command text. */
  readonly command: string | undefined;
  /** True when the command's result was an error. */
  readonly isError: boolean | undefined;
  /** The scope key the command's rows carry. */
  readonly scopeKey?: string | undefined;
}

/** Slack on each side of a command's run, for the clocks of the transcript and the reflog. */
export const GIT_COMMIT_SLACK_MS = 2_000;

const COMMITTING_SUBCOMMANDS = new Set([
  'commit',
  'merge',
  'rebase',
  'cherry-pick',
  'am',
  'revert',
]);
const NON_COMMITTING_FLAGS = new Set(['--help', '-h', '--dry-run']);
// Global options that take the next word as their value.
const OPTIONS_WITH_VALUE = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace']);

/**
 * The directory of each git invocation in `command` that can make commits, resolved against
 * `cwd` and any `-C` it carries. The command is split on unquoted `;`, `&`, `|` and newlines, and
 * each part is read word by word, so git named inside quotes, in an argument, or as another
 * program's input does not count, nor does a `--help` or `--dry-run` run.
 */
export function committingGitDirs(command: string, cwd: string): string[] {
  const dirs: string[] = [];
  for (const words of commandParts(command)) {
    let i = 0;
    while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i] ?? '')) i += 1;
    if (words[i] !== 'git') continue;
    i += 1;
    let dir = cwd;
    while (i < words.length && (words[i] ?? '').startsWith('-')) {
      const option = words[i] ?? '';
      if (OPTIONS_WITH_VALUE.has(option)) {
        if (option === '-C' && words[i + 1] !== undefined) dir = resolve(dir, words[i + 1] ?? '');
        i += 2;
      } else {
        i += 1;
      }
    }
    const subcommand = words[i];
    if (subcommand === undefined || !COMMITTING_SUBCOMMANDS.has(subcommand)) continue;
    if (words.slice(i + 1).some((w) => NON_COMMITTING_FLAGS.has(w))) continue;
    dirs.push(dir);
  }
  return dirs;
}

// The words of each part of a shell command, quotes removed. Unquoted `;`, `&`, `|`, `(`, `)` and
// newlines end a part.
function commandParts(command: string): string[][] {
  const parts: string[][] = [];
  let words: string[] = [];
  let word = '';
  let quote: '"' | "'" | null = null;
  let inWord = false;
  const endWord = () => {
    if (inWord) words.push(word);
    word = '';
    inWord = false;
  };
  const endPart = () => {
    endWord();
    if (words.length > 0) parts.push(words);
    words = [];
  };
  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i] ?? '';
    if (quote !== null) {
      if (ch === quote) quote = null;
      else if (ch === '\\' && quote === '"' && i + 1 < command.length) word += command.charAt(++i);
      else word += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
    } else if (ch === '\\' && i + 1 < command.length) {
      word += command.charAt(++i);
      inWord = true;
    } else if (';&|()\n'.includes(ch)) {
      endPart();
    } else if (ch === ' ' || ch === '\t') {
      endWord();
    } else {
      word += ch;
      inWord = true;
    }
  }
  endPart();
  return parts;
}

/**
 * One `git_commit` row per commit a checkout reached while one of the session's git commands
 * that make commits was running in it: between the command's issue and its result, with
 * `GIT_COMMIT_SLACK_MS` either side. A command that errored, or whose result is not yet in the
 * transcript, records nothing. Each checkout's reflog is read once per call. A row is keyed on the
 * session and the commit, so a commit seen twice is one row, stamped with the scope key of the
 * command that first saw it. `attribution: 'command_window'` marks the tie as timing: a commit
 * another actor made in the same checkout while the command ran is recorded too.
 */
export function sessionCommitEvents(
  sessionId: string,
  commands: readonly SessionCommand[],
): AuditEventInput[] {
  const logs = new Map<string, HeadLog | null>();
  const logOf = (dir: string) => {
    if (!logs.has(dir)) logs.set(dir, readHeadLog(dir));
    return logs.get(dir) ?? null;
  };
  const events = new Map<string, AuditEventInput>();
  for (const call of commands) {
    const { cwd, command } = call;
    if (call.isError === true || call.completedAt === undefined) continue;
    if (cwd === undefined || !isAbsolute(cwd) || command === undefined) continue;
    const from = Date.parse(call.occurredAt) - GIT_COMMIT_SLACK_MS;
    const to = Date.parse(call.completedAt) + GIT_COMMIT_SLACK_MS;
    if (!Number.isFinite(from) || !Number.isFinite(to)) continue;
    for (const dir of committingGitDirs(command, cwd)) {
      const log = logOf(dir);
      if (log === null) continue;
      for (const { commit, at, kind } of log.commits) {
        if (at < from || at > to) continue;
        const id = gitCommitId(sessionId, commit);
        if (events.has(id)) continue;
        const attributes: GitCommitAttributes = { commit, kind, attribution: 'command_window' };
        if (call.scopeKey !== undefined) attributes.scope_key = call.scopeKey;
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
  }
  return [...events.values()];
}
