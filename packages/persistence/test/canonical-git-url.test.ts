import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { canonicalGitUrl, canonicalRepoUrl } from '../src/egress-wire.ts';
import { sourceProjectId } from '../src/ids.ts';
import {
  resolveSshHost,
  UNSAFE_TEST_ONLY_setSshConfigPath,
  UNSAFE_TEST_ONLY_setSshHostAliases,
} from '../src/ssh-hosts.ts';

// This suite is ABOUT the parser, so it drops the process-wide empty-alias pin
// (test/setup/no-ssh-aliases.ts) and points the reader at a temp config.
//
// It does NOT mock `node:os` to move `homedir`, and that is the whole reason
// the path seam exists: the setup file imports ssh-hosts.ts before any test
// file runs, so the module's `homedir` binding is the real one long before a
// `vi.mock` could replace it. Mocking it here silently read the DEVELOPER'S own
// ~/.ssh/config — which is why an earlier version of this file passed the one
// case whose alias happened to exist on the author's laptop and failed the rest.

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-sshcfg-'));
  UNSAFE_TEST_ONLY_setSshHostAliases(null);
  UNSAFE_TEST_ONLY_setSshConfigPath(join(dir, 'config'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  UNSAFE_TEST_ONLY_setSshConfigPath(null);
  UNSAFE_TEST_ONLY_setSshHostAliases(new Map());
});

// Write `body` as the ssh config this suite reads (or a sibling beside it, for
// the Include cases). Re-points the reader, which also drops the parse cache.
function sshConfig(body: string, name = 'config'): void {
  writeFileSync(join(dir, name), body);
  UNSAFE_TEST_ONLY_setSshConfigPath(join(dir, 'config'));
}

describe('resolveSshHost', () => {
  it('resolves a literal alias to the HostName it names', () => {
    sshConfig('Host github-personal\n  HostName github.com\n  IdentityFile ~/.ssh/id_x\n');
    expect(resolveSshHost('github-personal')).toBe('github.com');
  });

  it('answers the host as written when there is no config at all', () => {
    expect(resolveSshHost('github.com')).toBe('github.com');
  });

  it('maps every alias of a block that names several', () => {
    sshConfig('Host gh-work gh-personal\n  HostName github.com\n');
    expect(resolveSshHost('gh-work')).toBe('github.com');
    expect(resolveSshHost('gh-personal')).toBe('github.com');
  });

  it('never STORES a pattern alias, so a host spelled like one is not rewritten', () => {
    // The sharp edge of the pattern filter. An ordinary host is already safe
    // from a `Host *` block because lookup is an exact map hit, so asserting on
    // one proves nothing about the filter — a host that IS the pattern is the
    // only reading that separates the two.
    sshConfig('Host *\n  HostName example.com\n');
    expect(resolveSshHost('*')).toBe('*');
  });

  it('leaves an ordinary host alone under a wildcard block', () => {
    // Holds because lookup is exact, not because of the filter above. Kept as
    // the statement of the overall behaviour a reader cares about.
    sshConfig('Host *\n  HostName example.com\n');
    expect(resolveSshHost('github.com')).toBe('github.com');
    expect(resolveSshHost('gitlab.com')).toBe('gitlab.com');
  });

  it('ignores a HostName carrying a token, which ssh expands per connection', () => {
    sshConfig('Host gh\n  HostName %h.example.com\n');
    expect(resolveSshHost('gh')).toBe('gh');
  });

  it('keeps the FIRST HostName for an alias, as ssh does', () => {
    sshConfig('Host gh\n  HostName github.com\nHost gh\n  HostName gitlab.com\n');
    expect(resolveSshHost('gh')).toBe('github.com');
  });

  it('ignores a commented-out mapping', () => {
    sshConfig('Host gh\n#  HostName github.com\n');
    expect(resolveSshHost('gh')).toBe('gh');
  });

  it('accepts the `Keyword = value` spelling', () => {
    sshConfig('Host = gh\n  HostName = github.com\n');
    expect(resolveSshHost('gh')).toBe('github.com');
  });

  it('follows an Include, including a single-directory glob', () => {
    mkdirSync(join(dir, 'config.d'), { recursive: true });
    writeFileSync(join(dir, 'config.d', 'work'), 'Host gh\n  HostName github.com\n');
    sshConfig('Include config.d/*\nHost other\n  HostName other.example\n');
    expect(resolveSshHost('gh')).toBe('github.com');
    expect(resolveSshHost('other')).toBe('other.example');
  });

  it('terminates on an Include cycle', () => {
    sshConfig('Include config\nHost gh\n  HostName github.com\n');
    expect(resolveSshHost('gh')).toBe('github.com');
  });

  it('matches an alias case-insensitively, as ssh does', () => {
    sshConfig('Host GitHub-Personal\n  HostName GitHub.com\n');
    expect(resolveSshHost('github-personal')).toBe('github.com');
  });
});

describe('canonicalGitUrl — the one reduction every surface shares', () => {
  const SPELLINGS = [
    'git@github-personal:acme/app',
    'git@github-personal:acme/app.git',
    'git@github.com:acme/app.git',
    'https://github.com/acme/app.git',
    'https://github.com/acme/app',
    'ssh://git@GitHub.com:22/acme/app.git',
  ];

  it('gives one key to every spelling of one repository', () => {
    sshConfig('Host github-personal\n  HostName github.com\n');
    expect([...new Set(SPELLINGS.map(canonicalGitUrl))]).toEqual(['github.com/acme/app']);
  });

  // The unification. The project id, the SCOPE KEY and the wire digest all
  // reduce through canonicalGitUrl, so "which repository is this" has one
  // answer on every surface. A scope key that split per spelling is not a
  // display bug: enrolment is matched by exact string, so a developer whose
  // clone keyed differently would forward nothing while the repository read as
  // enrolled — a coverage gap nothing reports.
  it('gives one SCOPE KEY to every spelling, so enrolment covers them all', () => {
    sshConfig('Host github-personal\n  HostName github.com\n');
    expect([...new Set(SPELLINGS.map(canonicalRepoUrl))]).toEqual(['github.com/acme/app']);
  });

  it('gives one project id to every spelling', () => {
    sshConfig('Host github-personal\n  HostName github.com\n');
    expect(new Set(SPELLINGS.map(sourceProjectId)).size).toBe(1);
  });

  it('folds the path case on a forge that ignores it', () => {
    // On GitHub `acme/App` and `acme/app` are one repository, so keeping the
    // case splits a repository that every clone of shares.
    expect(canonicalGitUrl('https://github.com/Acme/App.git')).toBe('github.com/acme/app');
    expect(canonicalGitUrl('git@github.com:ACME/APP.git')).toBe('github.com/acme/app');
    expect(canonicalRepoUrl('https://github.com/Acme/App')).toBe('github.com/acme/app');
    for (const forge of ['gitlab.com', 'bitbucket.org']) {
      expect(canonicalGitUrl(`https://${forge}/Acme/App.git`)).toBe(`${forge}/acme/app`);
    }
  });

  it('KEEPS the path case on a host not known to ignore it', () => {
    // The asymmetry this allowlist exists for. A self-hosted git over a
    // case-sensitive filesystem really does distinguish these, and folding
    // them would blend two repositories' egress with nothing to notice it.
    expect(canonicalGitUrl('git@git.example.com:acme/App.git')).toBe('git.example.com/acme/App');
    expect(canonicalGitUrl('git@git.example.com:acme/app.git')).toBe('git.example.com/acme/app');
    // A self-hosted GitHub Enterprise is case-insensitive too and is not
    // covered: nothing in a hostname says which software answers it, so it
    // misses the convergence rather than risking a collision.
    expect(canonicalGitUrl('https://github.acme-corp.com/Acme/App.git')).toBe(
      'github.acme-corp.com/Acme/App',
    );
  });

  it('folds the HOST case everywhere, which DNS makes safe', () => {
    expect(canonicalGitUrl('https://GitHub.COM/acme/app.git')).toBe('github.com/acme/app');
    expect(canonicalGitUrl('git@Git.Example.COM:acme/App.git')).toBe('git.example.com/acme/App');
  });

  it('does NOT merge two different repositories on one host', () => {
    expect(canonicalGitUrl('git@github.com:acme/app.git')).not.toBe(
      canonicalGitUrl('git@github.com:acme/other.git'),
    );
  });

  it('does NOT merge the same path on two different hosts', () => {
    expect(canonicalGitUrl('git@github.com:acme/app.git')).not.toBe(
      canonicalGitUrl('git@gitlab.com:acme/app.git'),
    );
  });

  it('keeps a path-only identity as itself, with nothing to converge', () => {
    const path = '/Users/someone/code/parent/.git/modules/oss';
    expect(canonicalGitUrl(path)).toBe(path);
  });
});
