/**
 * Every README that claims data stays on the machine has to be a page somebody
 * decided to make that claim on.
 *
 * `plugins/claude-code/test/privacy-claims.test.ts` holds the claims themselves
 * — that a locality sentence carries its `[^egress]` qualifier, that the
 * footnote names what crosses. What it cannot hold is the question of WHICH
 * files it runs over, and the reason is turbo rather than taste: that task's
 * `inputs` name two READMEs, so a new front door anywhere else in the tree left
 * its hash byte-identical (measured: `c1cad2119b086099` before and after adding
 * `web-ui/README.md`), and `ci.yml` restores `.turbo/cache` with restore-keys
 * across commits. The guard reddened locally and CI replayed a cached pass — a
 * derived check that never executes is worse than a hand-written list, because
 * it reads as though it covered everything.
 *
 * This package's `test` task is the one whose `inputs` hash the whole workspace
 * (`$TURBO_ROOT$/**\/*.md`, with the node_modules/dist/.turbo exclusions already
 * on it), which is the same reason `test-only-seam.test.js` lives here rather
 * than in the package it audits.
 *
 * The classified list stays in the plugin suite, which owns the tier split; this
 * reads it, so there is one source of truth rather than two that can disagree.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';

const CLASSIFIER = 'plugins/claude-code/test/privacy-claims.test.ts';

// Kept in step with LOCALITY_CLAIM in the plugin suite — asserted below rather
// than trusted, since a claim shape it matches and this one does not would make
// this guard silently narrower than the thing it guards.
const LOCALITY_CLAIM =
  /nothing (?:leaves|is sent)|never (?:leaves|send)|not sent to a model|no scanning happens off|scanned off your/i;

const repoFile = (relative) => readFileSync(join(REPO_ROOT, relative), 'utf8');

/**
 * The `name` of every row in the plugin suite's CLASSIFIED_READMES.
 *
 * Read out of the source rather than duplicated: two lists would be free to
 * disagree, and the one that disagreed silently would be this one.
 */
const classifiedReadmes = () => {
  const source = repoFile(CLASSIFIER);
  const block = /const CLASSIFIED_READMES = \[(.*?)\] as const;/s.exec(source);
  if (!block) throw new Error(`Could not find CLASSIFIED_READMES in ${CLASSIFIER}`);
  return [...block[1].matchAll(/name: '([^']+)'/g)].map((m) => m[1]);
};

/**
 * A fixture corpus other suites feed to a scanner — an input, not a page anyone
 * reads. Anchored on a path SEGMENT rather than `includes('/test/fixtures/')`,
 * which needs a leading slash and so misses the repo-root `test/fixtures/` tree.
 */
const isFixture = (path) => /(?:^|\/)test\/fixtures\//.test(path);

/**
 * Every README the working tree holds, staged or not.
 *
 * `--others --exclude-standard` because the index alone cannot see a README a
 * contributor has just written, which would defer the failure to whoever ran
 * `git add`. `existsSync` because `--cached` reports the index regardless of
 * what is on disk, so a README deleted from the worktree but not yet staged
 * stays in the listing and reading it throws ENOENT — a failure attributed to
 * this guard while naming neither its purpose nor the real cause.
 */
const treeReadmes = () => {
  let out;
  try {
    out = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 << 20,
    });
  } catch (cause) {
    throw new Error(
      'Could not list README files with `git ls-files`. This guard audits the real workspace ' +
        'layout, so it must run inside a git checkout.',
      { cause },
    );
  }
  return out
    .split('\n')
    .filter(Boolean)
    .filter((p) => /(?:^|\/)README\.md$/i.test(p))
    .filter((p) => !isFixture(p))
    .filter((p) => existsSync(join(REPO_ROOT, p)));
};

describe('locality-claim coverage', () => {
  // Without this the comparison below runs over an empty expectation and passes
  // however the tree looks — the classifier moving or being renamed would read
  // as "nothing to classify" rather than as a broken guard.
  it('finds the classified list in the plugin suite', () => {
    expect(classifiedReadmes().length).toBeGreaterThan(0);
  });

  // Same shape: an empty listing satisfies any set comparison against an empty
  // classified list, so the walk has to be shown to see the tree at all.
  it('finds READMEs in the tree', () => {
    expect(treeReadmes()).toContain('README.md');
  });

  /**
   * The two regexes are copies across a package wall (this suite is plain JS and
   * cannot import the TS one), so they are compared as WHOLE literals, flags
   * included — not by containment.
   *
   * Containment is asymmetric and leaks in both directions. Append an
   * alternative to the TS pattern and its source still CONTAINS the narrow copy
   * as a prefix, so this passes while the walk below keeps using the narrow one
   * and a README matching only the new alternative is never classified. Drop a
   * trailing alternative from this copy and it becomes a prefix of the TS one,
   * which also passes. Only a change in the middle would have reddened.
   */
  it('uses the same locality-claim pattern as the suite it guards', () => {
    const source = repoFile(CLASSIFIER);
    expect(source).toContain(`/${LOCALITY_CLAIM.source}/i`);
  });

  /**
   * A front door that says "nothing leaves your machine" and is not classified
   * reddens here rather than shipping unread. This is the rule the hand-written
   * two-entry list could not state, and the reason `cli/README.md` carried an
   * unqualified locality claim for as long as it did.
   */
  it('classifies every README in the tree that makes a locality claim', () => {
    const claiming = treeReadmes().filter((p) => LOCALITY_CLAIM.test(repoFile(p)));
    expect(claiming.sort()).toEqual(classifiedReadmes().sort());
  });
});
