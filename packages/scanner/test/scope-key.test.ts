import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scopeKeysUnder } from '../src/scope-key.ts';

// The userinfo in an scp-form remote reads as an email address to a scanner,
// so the fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

// The lookup on its own, against a real fixture repository and the real
// resolver. Which capture carries which key, and how often a scan reads a
// repository, are pinned through scanWorktree in ./scan.test.ts.
describe('scopeKeysUnder', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aka-scope-key-'));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('resolves a relative scan root against the process directory before walking up', () => {
    // `/aka:scan --dir api` hands the scanner the root as typed. The resolver
    // returns no key for a directory that is not absolute, so a root left
    // relative would leave every file keyless even though the repository two
    // levels above it has a remote.
    mkdirSync(join(tmp, '.git'), { recursive: true });
    writeFileSync(
      join(tmp, '.git', 'config'),
      `[remote "origin"]\n\turl = ${gitUser}github.com:acme/work.git\n`,
    );
    mkdirSync(join(tmp, 'packages', 'api', 'src'), { recursive: true });
    // path.resolve reads the process directory through process.cwd(); every
    // later read uses the absolute path it returns.
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(join(tmp, 'packages'));
    try {
      expect(scopeKeysUnder('api')('src/api-a.ts')).toBe('github.com/acme/work');
    } finally {
      cwd.mockRestore();
    }
  });

  describe('repositoryOf', () => {
    // The lookup also says which directory it answered from, so a ledger row can
    // record the repository's root beside its key.
    const gitRepo = (dir: string, remote: string): void => {
      mkdirSync(join(dir, '.git'), { recursive: true });
      writeFileSync(
        join(dir, '.git', 'config'),
        `[remote "origin"]\n\turl = ${gitUser}github.com:${remote}.git\n`,
      );
    };

    it("answers a nested repository's file with that repository's directory and key", () => {
      gitRepo(tmp, 'acme/work');
      gitRepo(join(tmp, 'tools', 'mine'), 'me/personal');
      mkdirSync(join(tmp, 'tools', 'mine', 'src'), { recursive: true });
      const lookup = scopeKeysUnder(tmp);

      expect(lookup.repositoryOf('tools/mine/src/a.ts')).toEqual({
        root: join(tmp, 'tools', 'mine'),
        key: 'github.com/me/personal',
      });
      // The plain call is the key of the same answer.
      expect(lookup('tools/mine/src/a.ts')).toBe('github.com/me/personal');
    });

    it("answers the scan root's own repository's file with the directory holding its `.git`", () => {
      gitRepo(tmp, 'acme/work');
      mkdirSync(join(tmp, 'src'), { recursive: true });
      const lookup = scopeKeysUnder(tmp);

      expect(lookup.repositoryOf('src/a.ts')).toEqual({ root: tmp, key: 'github.com/acme/work' });
      expect(lookup.repositoryOf('b.ts')).toEqual({ root: tmp, key: 'github.com/acme/work' });
    });

    it('answers a scan root inside a repository with the repository above it', () => {
      gitRepo(tmp, 'acme/work');
      mkdirSync(join(tmp, 'packages', 'api', 'src'), { recursive: true });
      const lookup = scopeKeysUnder(join(tmp, 'packages', 'api'));

      expect(lookup.repositoryOf('src/a.ts')).toEqual({ root: tmp, key: 'github.com/acme/work' });
    });

    it('answers a repository with no remote with its directory and no key', () => {
      mkdirSync(join(tmp, '.git'), { recursive: true });
      writeFileSync(join(tmp, '.git', 'config'), '[core]\n\tbare = false\n');
      mkdirSync(join(tmp, 'src'), { recursive: true });

      expect(scopeKeysUnder(tmp).repositoryOf('src/a.ts')).toEqual({
        root: tmp,
        key: undefined,
      });
    });

    it('answers a file in no repository with neither', () => {
      mkdirSync(join(tmp, 'src'), { recursive: true });

      expect(scopeKeysUnder(tmp).repositoryOf('src/a.ts')).toEqual({
        root: undefined,
        key: undefined,
      });
    });

    it('does not answer from a `.git` that is gone: it climbs to the repository around', () => {
      gitRepo(tmp, 'acme/work');
      gitRepo(join(tmp, 'clone'), 'me/personal');
      mkdirSync(join(tmp, 'clone', 'src'), { recursive: true });
      rmSync(join(tmp, 'clone', '.git'), { recursive: true, force: true });

      expect(scopeKeysUnder(tmp).repositoryOf('clone/src/a.ts')).toEqual({
        root: tmp,
        key: 'github.com/acme/work',
      });
    });
  });
});
