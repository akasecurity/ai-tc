import { describe, expect, it } from 'vitest';

import { canonicalGitUrl, canonicalRepoUrl } from '../src/egress-wire.ts';
import { sourceProjectId } from '../src/ids.ts';

// The one reduction every identity on this machine goes through. PURE: it reads
// no file and consults no machine state, which is what lets the web dashboard
// compile this package as its own source. An SSH `Host` alias is therefore not
// resolved here, and a clone made through one keys to the alias — tracked
// separately, because resolving it means reading ~/.ssh/config and that cannot
// live on a path the dashboard's build compiles.

describe('canonicalGitUrl — the one reduction every surface shares', () => {
  // Every spelling of one repository that this reduction converges WITHOUT an
  // alias map: scp and scheme form, with and without `.git`, any case of host
  // or path, a userinfo, a port, a trailing slash. An SSH `Host` alias is NOT
  // among them — resolving one means reading ~/.ssh/config, which this package
  // deliberately does not do (see the module header), so a clone made through
  // an alias still keys to the alias and is tracked separately.
  const SPELLINGS = [
    'git@github.com:acme/app.git',
    'git@github.com:Acme/App',
    'https://github.com/acme/app.git',
    'https://github.com/acme/app/',
    'ssh://git@GitHub.com:22/acme/app.git',
  ];

  it('gives one key to every spelling of one repository', () => {
    expect([...new Set(SPELLINGS.map((url) => canonicalGitUrl(url)))]).toEqual([
      'github.com/acme/app',
    ]);
  });

  // The unification. The project id, the SCOPE KEY and the wire digest all
  // reduce through canonicalGitUrl, so "which repository is this" has one
  // answer on every surface. A scope key that split per spelling is not a
  // display bug: enrolment is matched by exact string, so a developer whose
  // clone keyed differently would forward nothing while the repository read as
  // enrolled — a coverage gap nothing reports.
  it('gives one SCOPE KEY to every spelling, so enrolment covers them all', () => {
    expect([...new Set(SPELLINGS.map((url) => canonicalRepoUrl(url)))]).toEqual([
      'github.com/acme/app',
    ]);
  });

  it('gives one project id to every spelling', () => {
    expect(new Set(SPELLINGS.map((url) => sourceProjectId(url))).size).toBe(1);
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

  it('reduces every transport of one forge host to one key', () => {
    for (const remote of [
      'https://github.com/Acme/App.git',
      'http://github.com/Acme/App.git',
      'git://github.com/Acme/App.git',
      'git@github.com:Acme/App.git',
      'ssh://git@github.com/Acme/App.git',
    ]) {
      expect(canonicalGitUrl(remote)).toBe('github.com/acme/app');
    }
    // And the scope key with it, so an org enrolment of github.com covers this
    // machine whichever transport it cloned over — the silent no-forward this
    // guards against.
    expect(canonicalRepoUrl('https://github.com/acme/app')).toBe('github.com/acme/app');
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
