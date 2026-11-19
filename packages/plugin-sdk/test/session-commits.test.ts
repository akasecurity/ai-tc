import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { gitCommitId } from '@akasecurity/persistence';
import { GitCommitAttributes } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { readRegularFileTail } from '../src/regular-file.ts';
import { readHeadLog } from '../src/repo.ts';
import type { SessionCommand } from '../src/session-commits.ts';
import {
  committingGitDirs,
  GIT_COMMIT_SLACK_MS,
  headLogMemo,
  sessionCommitEvents,
} from '../src/session-commits.ts';

const ZERO = '0'.repeat(40);
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const C = 'c'.repeat(40);
const D = 'd'.repeat(40);
const E = 'e'.repeat(40);
const T0 = Date.parse('2026-11-17T10:00:00.000Z');

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-head-commits-'));
});

afterEach(() => {
  removeTree(root);
});

/** Runs git in `dir` with a fixed identity and no user or system config. */
function realGit(dir: string): (...args: string[]) => string {
  return (...args) =>
    execFileSync('git', args, {
      cwd: dir,
      encoding: 'utf8',
      env: {
        PATH: '/usr/bin:/bin:/usr/local/bin',
        HOME: dir,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_AUTHOR_NAME: 'Dev',
        GIT_AUTHOR_EMAIL: 'dev@example.com',
        GIT_COMMITTER_NAME: 'Dev',
        GIT_COMMITTER_EMAIL: 'dev@example.com',
      },
    }).trim();
}

function reflogLine(from: string, to: string, at: number, message: string, name = 'Dev'): string {
  return `${from} ${to} ${name} <dev@example.com> ${String(Math.floor(at / 1000))} +0000\t${message}\n`;
}

/** A clone at `dir` whose reflog holds `lines`. */
function cloneWithReflog(dir: string, lines: string[]): string {
  mkdirSync(join(dir, '.git', 'logs'), { recursive: true });
  writeFileSync(join(dir, '.git', 'HEAD'), 'ref: refs/heads/feat/x\n');
  writeFileSync(join(dir, '.git', 'logs', 'HEAD'), lines.join(''));
  return dir;
}

/** A command that ran from `T0 + issued` to `T0 + done` (milliseconds). */
function call(
  command: string,
  issued: number,
  done: number | undefined,
  extra: Partial<SessionCommand> = {},
): SessionCommand {
  return {
    cwd: root,
    occurredAt: new Date(T0 + issued).toISOString(),
    completedAt: done === undefined ? undefined : new Date(T0 + done).toISOString(),
    command,
    isError: false,
    ...extra,
  };
}

describe('readRegularFileTail', () => {
  it('reads a file no larger than the cap whole, and says so', () => {
    const path = join(root, 'f');
    writeFileSync(path, 'x'.repeat(16));
    expect(readRegularFileTail(path, 16)).toEqual({ text: 'x'.repeat(16), truncated: false });
  });

  it('reads the last bytes of a larger file and marks it cut', () => {
    const path = join(root, 'f');
    writeFileSync(path, 'old\nnewest\n');
    expect(readRegularFileTail(path, 7)).toEqual({ text: 'newest\n', truncated: true });
  });

  it('throws for a missing file and for a directory', () => {
    expect(() => readRegularFileTail(join(root, 'missing'), 8)).toThrow();
    expect(() => readRegularFileTail(root, 8)).toThrow();
  });
});

describe('readHeadLog', () => {
  it('reads only the moves that make commits, and a rebase only at its last step', () => {
    cloneWithReflog(root, [
      reflogLine(ZERO, A, T0 - 60_000, 'clone: from https://github.com/acme/api'),
      reflogLine(A, B, T0, 'commit: add retries'),
      reflogLine(B, A, T0 + 1_000, 'checkout: moving from feat/x to main'),
      reflogLine(A, C, T0 + 2_000, "merge feat/y: Merge made by the 'ort' strategy."),
      reflogLine(C, C, T0 + 3_000, 'reset: moving to HEAD'),
      reflogLine(C, D, T0 + 4_000, 'pull: Fast-forward'),
      reflogLine(D, A, T0 + 5_000, 'rebase (start): checkout main'),
      reflogLine(A, B, T0 + 5_100, 'rebase (pick): someone else’s commit'),
      reflogLine(B, E, T0 + 5_200, 'rebase (finish): returning to refs/heads/feat/x'),
    ]);
    expect(readHeadLog(root)).toEqual([
      { commit: B, at: T0, kind: 'commit' },
      { commit: C, at: T0 + 2_000, kind: 'merge' },
      { commit: E, at: T0 + 5_000, kind: 'rebase' },
    ]);
  });

  it('leaves out a fast-forward merge, cherry-pick or rebase', () => {
    cloneWithReflog(root, [
      reflogLine(A, B, T0, 'merge main: Fast-forward'),
      reflogLine(B, C, T0 + 1_000, 'cherry-pick: fast-forward'),
      reflogLine(C, D, T0 + 2_000, 'rebase (start): checkout main'),
      reflogLine(D, D, T0 + 3_000, 'rebase (finish): returning to refs/heads/feat/x'),
      reflogLine(D, E, T0 + 4_000, 'rebase -i (start): checkout main'),
      reflogLine(E, E, T0 + 5_000, 'rebase -i (finish): returning to refs/heads/feat/x'),
    ]);
    expect(readHeadLog(root)).toEqual([]);
  });

  it('leaves out the fast-forwards git itself wrote, and keeps a merge commit', () => {
    const git = realGit(root);
    git('init', '-q', '-b', 'main');
    writeFileSync(join(root, 'a.txt'), 'a\n');
    git('add', 'a.txt');
    git('commit', '-q', '-m', 'one');
    const upstream = join(root, '.upstream');
    git('clone', '-q', root, upstream);
    const other = realGit(upstream);
    writeFileSync(join(upstream, 'a.txt'), 'b\n');
    other('commit', '-q', '-am', 'two, made elsewhere');
    git('fetch', '-q', upstream, 'main:elsewhere');
    git('checkout', '-q', '-b', 'ff-merge', 'main');
    git('merge', '-q', '--ff-only', 'elsewhere');
    git('checkout', '-q', '-b', 'ff-pick', 'main');
    git('cherry-pick', '--ff', 'elsewhere');
    git('checkout', '-q', '-b', 'ff-rebase', 'main');
    git('rebase', '-q', 'elsewhere');
    git('checkout', '-q', '-b', 'no-ff', 'main');
    writeFileSync(join(root, 'b.txt'), 'b\n');
    git('add', 'b.txt');
    git('commit', '-q', '-m', 'three');
    git('merge', '-q', '--no-ff', '--no-edit', 'elsewhere');
    const log = readHeadLog(root) ?? [];
    expect(log.map((c) => c.commit)).not.toContain(git('rev-parse', 'elsewhere'));
    expect(log.map((c) => c.kind)).toEqual(['commit', 'commit', 'merge']);
    expect(log.at(-1)?.commit).toBe(git('rev-parse', 'HEAD'));
  });

  it("reads a linked worktree's own reflog", () => {
    const gitdir = join(root, '.git', 'worktrees', 'wt');
    mkdirSync(join(gitdir, 'logs'), { recursive: true });
    writeFileSync(join(gitdir, 'logs', 'HEAD'), reflogLine(A, B, T0, 'commit: from the worktree'));
    const checkout = join(root, 'wt');
    mkdirSync(checkout, { recursive: true });
    writeFileSync(join(checkout, '.git'), `gitdir: ${gitdir}\n`);
    expect(readHeadLog(checkout)).toEqual([{ commit: B, at: T0, kind: 'commit' }]);
  });

  it('keeps the first line of a reflog of exactly the read size', () => {
    const first = reflogLine(A, B, T0, 'commit: the first line');
    const filler = reflogLine(B, C, T0 + 1, 'checkout: moving from a to b');
    const size = 256 * 1024;
    const fillers = Math.floor((size - first.length) / filler.length);
    const pad = size - first.length - fillers * filler.length;
    cloneWithReflog(root, [first, filler.repeat(fillers), ' '.repeat(pad)]);
    expect(readHeadLog(root)?.map((c) => c.commit)).toEqual([B]);
  });

  it('drops a first line the read starts inside, even when what is left of it still parses', () => {
    const old64 = 'f'.repeat(64);
    const new64 = '1'.repeat(64);
    const cut = 10;
    const first = reflogLine(old64, new64, T0, 'commit: cut in its old id');
    const filler = reflogLine(B, C, T0 + 1, 'checkout: moving from a to b');
    const size = 256 * 1024 + cut;
    const fillers = Math.floor((size - first.length) / filler.length);
    const pad = size - first.length - fillers * filler.length;
    cloneWithReflog(root, [first, filler.repeat(fillers), ' '.repeat(pad)]);
    const fragment = first.slice(cut);
    expect(fragment.startsWith('f'.repeat(54) + ' ')).toBe(true);
    expect(readHeadLog(root)).toEqual([]);
  });

  it('reads the tail of a longer reflog, multi-byte names included', () => {
    cloneWithReflog(root, []);
    const log = join(root, '.git', 'logs', 'HEAD');
    const old = reflogLine(A, C, T0 - 10_000, 'commit: old', 'Zoë Ŝtrâße');
    appendFileSync(log, old.repeat(Math.ceil((300 * 1024) / old.length)));
    appendFileSync(log, reflogLine(C, B, T0, 'commit: newest', 'Zoë Ŝtrâße'));
    expect(readHeadLog(root)).toEqual([
      { commit: C, at: T0 - 10_000, kind: 'commit' },
      { commit: B, at: T0, kind: 'commit' },
    ]);
  });

  it('answers null outside a checkout or without a reflog', () => {
    expect(readHeadLog(root)).toBeNull();
    mkdirSync(join(root, '.git'));
    expect(readHeadLog(root)).toBeNull();
  });
});

describe('committingGitDirs', () => {
  it.each([
    'git commit -m "x"',
    'git add -A && git commit -m "add retries"',
    'FOO=1 git -c user.name=x commit --amend --no-edit',
    'git merge feat/y',
    'git rebase main',
    'git cherry-pick abc123',
    'git am < patch',
    'git revert HEAD',
    'git commit -F - <<EOF\nadd retries\nEOF',
    "cat <<'EOF' > notes\ngit commit\nEOF\ngit commit -m x",
    'git --work-tree=../wt commit -m x',
  ])('finds the commit in %s', (command) => {
    expect(committingGitDirs(command, '/w')).toEqual(['/w']);
  });

  it.each([
    'git log --grep=commit',
    'git merge-base --is-ancestor a b',
    'git commit --help',
    'git commit --dry-run',
    "echo 'remember to git commit' && ls",
    'cat docs/git-commit.txt',
    'echo "git merge main"',
    'git status',
    'cat <<EOF\ngit commit\nEOF',
    'cat <<-EOF\n\tgit merge main\n\tEOF',
    'cat <<EOF\n\tEOF\ngit commit\nEOF',
    'cat <<A <<B\ngit commit\nA\ngit commit\nB',
    'git --git-dir=/x commit -m x',
    'git --git-dir /x commit -m x',
  ])('finds none in %s', (command) => {
    expect(committingGitDirs(command, '/w')).toEqual([]);
  });

  it('reads -C as the directory the commit lands in', () => {
    expect(
      committingGitDirs('git -C ../other commit -m x; git -C /abs merge y', '/w/repo'),
    ).toEqual(['/w/other', '/abs']);
  });
});

describe('sessionCommitEvents', () => {
  it('records each commit HEAD reached while the command ran, as a command_window row', () => {
    cloneWithReflog(root, [reflogLine(A, B, T0 + 1_000, 'commit: add retries')]);
    const events = sessionCommitEvents('session-1', [
      call('git commit -m x', 0, 3_000, { scopeKey: 'k1' }),
    ]);
    expect(events).toEqual([
      {
        id: gitCommitId('session-1', B),
        eventType: 'git_commit',
        parentId: 'session-1',
        rootSessionId: 'session-1',
        startedAt: new Date(T0 + 1_000).toISOString(),
        attributes: { commit: B, kind: 'commit', attribution: 'command_window', scope_key: 'k1' },
      },
    ]);
    expect(GitCommitAttributes.safeParse(events[0]?.attributes).success).toBe(true);
  });

  it('records nothing for a command that errored or whose result is not in yet', () => {
    cloneWithReflog(root, [reflogLine(A, B, T0 + 1_000, 'commit: x')]);
    expect(
      sessionCommitEvents('s', [
        call('git commit -m x', 0, 3_000, { isError: true }),
        call('git commit -m x', 0, undefined),
      ]),
    ).toEqual([]);
  });

  it('leaves out a commit another actor made in the checkout after the command finished', () => {
    cloneWithReflog(root, [
      reflogLine(A, B, T0 + 1_000, 'commit: the command'),
      reflogLine(B, C, T0 + 3_000 + GIT_COMMIT_SLACK_MS + 1_000, 'commit: someone else, later'),
    ]);
    const events = sessionCommitEvents('s', [call('git commit -m x', 0, 3_000)]);
    expect(events.map((e) => e.attributes?.commit)).toEqual([B]);
  });

  it('records a commit once for two commands that saw it, and the same rows on a second call', () => {
    cloneWithReflog(root, [reflogLine(A, B, T0 + 1_000, 'commit: x')]);
    const commands = [call('git commit -m x', 0, 3_000), call('git commit --amend', 500, 2_000)];
    const first = sessionCommitEvents('s', commands);
    expect(first).toHaveLength(1);
    expect(sessionCommitEvents('s', commands)).toEqual(first);
  });

  it('stamps a commit two commands saw with the scope key of the first', () => {
    cloneWithReflog(root, [reflogLine(A, B, T0 + 1_000, 'commit: x')]);
    const events = sessionCommitEvents('s', [
      call('git commit -m x', 0, 3_000, { scopeKey: 'first' }),
      call('git commit --amend', 500, 2_000, { scopeKey: 'second' }),
    ]);
    expect(events.map((e) => e.attributes?.scope_key)).toEqual(['first']);
  });

  it('reads a checkout once through a shared memo, across sessions', () => {
    cloneWithReflog(root, [reflogLine(A, B, T0 + 1_000, 'commit: x')]);
    const headLogOf = headLogMemo();
    const command = [call('git commit -m x', 0, 3_000)];
    expect(sessionCommitEvents('session-1', command, headLogOf)).toHaveLength(1);
    cloneWithReflog(root, [reflogLine(A, C, T0 + 1_000, 'commit: rewritten')]);
    const second = sessionCommitEvents('session-2', command, headLogOf);
    expect(second.map((e) => e.attributes?.commit)).toEqual([B]);
    expect(sessionCommitEvents('session-2', command).map((e) => e.attributes?.commit)).toEqual([C]);
  });

  it('gives each of two sessions running in one checkout its own row for the same commit', () => {
    cloneWithReflog(root, [reflogLine(A, B, T0 + 1_000, 'commit: x')]);
    const command = [call('git commit -m x', 0, 3_000)];
    const one = sessionCommitEvents('session-1', command);
    const two = sessionCommitEvents('session-2', command);
    expect([one[0]?.id, two[0]?.id]).toEqual([
      gitCommitId('session-1', B),
      gitCommitId('session-2', B),
    ]);
    expect(two[0]?.attributes?.attribution).toBe('command_window');
  });

  it('reads a reflog git itself wrote', () => {
    const git = realGit(root);
    git('init', '-q', '-b', 'main');
    writeFileSync(join(root, 'a.txt'), 'a\n');
    git('add', 'a.txt');
    const issued = Date.now() - 1_000;
    git('commit', '-q', '-m', 'first');
    const head = git('rev-parse', 'HEAD');
    const events = sessionCommitEvents('s', [
      {
        cwd: root,
        occurredAt: new Date(issued).toISOString(),
        completedAt: new Date().toISOString(),
        command: 'git commit -m first',
        isError: false,
      },
    ]);
    expect(events.map((e) => [e.attributes?.commit, e.attributes?.kind])).toEqual([
      [head, 'commit'],
    ]);
  });
});
