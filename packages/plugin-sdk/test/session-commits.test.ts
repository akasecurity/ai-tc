import { appendFileSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { gitCommitId } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { readHeadCommits } from '../src/repo.ts';
import { GIT_COMMIT_WINDOW_MS, sessionCommitEvents } from '../src/session-commits.ts';

const ZERO = '0'.repeat(40);
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const C = 'c'.repeat(40);
const D = 'd'.repeat(40);
const T0 = Date.parse('2026-11-17T10:00:00.000Z');

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-head-commits-'));
});

afterEach(() => {
  removeTree(root);
});

function reflogLine(from: string, to: string, at: number, message: string): string {
  return `${from} ${to} Dev Person <dev@example.com> ${String(Math.floor(at / 1000))} +0000\t${message}\n`;
}

/** A clone at `dir` whose reflog holds `lines`. */
function cloneWithReflog(dir: string, lines: string[]): string {
  mkdirSync(join(dir, '.git', 'logs'), { recursive: true });
  writeFileSync(join(dir, '.git', 'HEAD'), 'ref: refs/heads/feat/x\n');
  writeFileSync(join(dir, '.git', 'logs', 'HEAD'), lines.join(''));
  return dir;
}

describe('readHeadCommits', () => {
  it('reads the commits HEAD reached in the window, oldest first, and skips other moves', () => {
    cloneWithReflog(root, [
      reflogLine(ZERO, A, T0 - 60_000, 'clone: from https://github.com/acme/api'),
      reflogLine(A, B, T0, 'commit: add retries'),
      reflogLine(B, A, T0 + 1_000, 'checkout: moving from feat/x to main'),
      reflogLine(A, C, T0 + 2_000, 'merge feat/y: Fast-forward'),
      reflogLine(C, C, T0 + 3_000, 'reset: moving to HEAD'),
      reflogLine(C, D, T0 + 4_000, 'pull: Fast-forward'),
      reflogLine(D, A, T0 + 5_000, 'rebase (finish): returning to refs/heads/feat/x'),
    ]);
    expect(readHeadCommits(root, T0 - 1_000, T0 + 10_000)).toEqual([
      { commit: B, at: T0, kind: 'commit' },
      { commit: C, at: T0 + 2_000, kind: 'merge' },
      { commit: A, at: T0 + 5_000, kind: 'rebase' },
    ]);
    expect(readHeadCommits(root, T0 + 1_000, T0 + 3_000)).toEqual([
      { commit: C, at: T0 + 2_000, kind: 'merge' },
    ]);
  });

  it("reads a linked worktree's own reflog", () => {
    const gitdir = join(root, '.git', 'worktrees', 'wt');
    mkdirSync(join(gitdir, 'logs'), { recursive: true });
    writeFileSync(join(gitdir, 'logs', 'HEAD'), reflogLine(A, B, T0, 'commit: from the worktree'));
    const checkout = join(root, 'wt');
    mkdirSync(checkout, { recursive: true });
    writeFileSync(join(checkout, '.git'), `gitdir: ${gitdir}\n`);
    expect(readHeadCommits(checkout, T0, T0)).toEqual([{ commit: B, at: T0, kind: 'commit' }]);
  });

  it('reads only the tail of a long reflog', () => {
    cloneWithReflog(root, []);
    const log = join(root, '.git', 'logs', 'HEAD');
    const old = reflogLine(A, C, T0 - 1, 'commit: old');
    appendFileSync(log, old.repeat(Math.ceil((300 * 1024) / old.length)));
    appendFileSync(log, reflogLine(C, B, T0, 'commit: newest'));
    expect(readHeadCommits(root, T0, T0)).toEqual([{ commit: B, at: T0, kind: 'commit' }]);
  });

  it('answers nothing outside a checkout or without a reflog', () => {
    expect(readHeadCommits(root, 0, Number.MAX_SAFE_INTEGER)).toEqual([]);
    mkdirSync(join(root, '.git'));
    expect(readHeadCommits(root, 0, Number.MAX_SAFE_INTEGER)).toEqual([]);
  });
});

describe('sessionCommitEvents', () => {
  it('records the commits a committing git command reached, once each, under the session', () => {
    cloneWithReflog(root, [
      reflogLine(A, B, T0 + 5_000, 'commit: add retries'),
      reflogLine(B, C, T0 + GIT_COMMIT_WINDOW_MS + 60_000, 'commit: much later'),
    ]);
    const at = new Date(T0).toISOString();
    const events = sessionCommitEvents('session-1', [
      { cwd: root, occurredAt: at, command: 'git add . && git commit -m "x"', scopeKey: 'k1' },
      { cwd: root, occurredAt: at, command: 'git commit --amend', scopeKey: 'k2' },
      { cwd: root, occurredAt: at, command: 'git status' },
      { cwd: 'relative/dir', occurredAt: at, command: 'git commit -m y' },
      { cwd: root, occurredAt: at, command: undefined },
    ]);
    expect(events).toEqual([
      {
        id: gitCommitId('session-1', B),
        eventType: 'git_commit',
        parentId: 'session-1',
        rootSessionId: 'session-1',
        startedAt: new Date(T0 + 5_000).toISOString(),
        attributes: { commit: B, kind: 'commit', branch: 'feat/x', scope_key: 'k1' },
      },
    ]);
  });
});
