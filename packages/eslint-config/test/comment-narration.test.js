import { Linter } from 'eslint';
import { describe, expect, it } from 'vitest';

import { commentNarrationPlugin, commentNarrationRules } from '../src/index.js';

// Driven through a real `Linter` rather than asserted against the rule object:
// a shape assertion passes on a value nothing enforces, and what a reader needs
// to know is which comments are refused — a question only the linter answers.
//
// The rule's whole risk is the OTHER direction. A comment ban that fires on
// prose, a hex colour or a licence header would be disabled within a week, and a
// disable directive is how a ban stops meaning anything. Most of what follows
// pins what it must NOT touch.
const linter = new Linter();

const run = (code, opts = {}) =>
  linter
    .verify(code, {
      plugins: { 'comment-narration': commentNarrationPlugin },
      languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      rules: commentNarrationRules(opts),
    })
    .filter((m) => m.ruleId === 'comment-narration/no-process-narration');

const kinds = (code, opts) => run(code, opts).map((m) => m.message);

describe('no-process-narration', () => {
  it.each([
    ['a plan path', '// see `plans/2026-09-14-u9-guard-core.md` for the shape'],
    ['an LLD reference', '// the LLD calls this the floor'],
    ['a unit number', '// Unit 8 ships the gateway'],
    ['a unit number with a minor', '// Unit 10.1 fills in the request table'],
    ['a task number', '// task 9.2 widened this'],
    ['a section number', '// §3.1 names the order'],
    ['a review response', '// review response 4 corrected this'],
    ['an rr shorthand', '// rr2 reopened it'],
    ['an issue ref', '// ai-tc #540 is on the pin'],
    ['a bare issue number', '// corrected in #426'],
    ['a PR label', '// PR 3/5 moved it'],
    ['a decision label', '// D-08 locks this axis'],
    ['a finding label', '// closes the F-04 race'],
    ['an invariant label', '// INV-8 forbids the host'],
    ['a commit SHA', '// pinned at oss@659b564e'],
    ['a bare SHA', '// NARROWED at the 6178a86b bump'],
    ['a dated decision', '// by owner decision (2026-09-24)'],
    ['a dated bump', '// NARROWED at the 2026-08-19 bump'],
  ])('fires on %s', (_kind, code) => {
    expect(run(code)).toHaveLength(1);
  });

  it.each([
    [
      'plain rationale',
      '// findingsTotal alone is the wrong gate: a healthy fleet has zero findings',
    ],
    [
      'a mandated index justification',
      '// drives the newest-first read; without it the plan was a seq scan',
    ],
    ['an eslint directive', '// eslint-disable-next-line n/no-process-env -- the one door'],
    ['a ts directive with a reason', '// @ts-expect-error the stub omits #internal on purpose'],
    ['a JSDoc tag block', '/** @param id the tenant whose rows to read */'],
    ['an SPDX header', '// SPDX-License-Identifier: Apache-2.0 (c) 2026'],
    ['a hex colour', '// surface token, was #1a1a1a before the tonal pass'],
    ['a short hex colour', '// #fff on dark, #000 on light'],
    ['an ISO timestamp', '// retained until 2026-01-01T00:00:00Z, then purged'],
    ['an HTTP status', '// a 404 here means the pack was unpublished'],
    ['a port number', '// the registry answers on 4100'],
    ['an ordinary number', '// 12 installed packs is the healthy floor'],
    ['a word that looks hex-ish', '// the decaffeinated path skips the worker'],
    ['a dated model id', '// the vendor documents claude-haiku-4-5-20251001 as the versioned id'],
    ['a model id with an @ suffix', '// claude-3-5-sonnet@20240620 is the pinned alias'],
    [
      'a long decimal constant',
      '// STATUS_DLL_INIT_FAILED, exit 3221225794: the child never starts',
    ],
    ['a bare fixture date', '// the 2026-01-01 email row falls outside the window entirely'],
    ['a date in sample output', '// renders as: secret/aws, seen 3 times, first 2026-07-27'],
    [
      'a section of the conventions file',
      '// authorizes the send, which is what CLAUDE.md §4 promises',
    ],
    ['a section of a README', '// §2 of the README names the seam'],
    [
      'a section of an external standard',
      "// RFC 9110 §5.5's own leading and trailing whitespace set",
    ],
    ['a section of a TC39 spec', '// per ECMA-262 §13.15, assignment is right-associative'],
  ])('stays silent on %s', (_kind, code) => {
    expect(run(code)).toEqual([]);
  });

  it('names the kind and the matching text, so the fix is obvious', () => {
    expect(kinds('// widened by Unit 11 since')[0]).toContain('a unit number');
    expect(kinds('// widened by Unit 11 since')[0]).toContain('Unit 11');
  });

  it('names the repo-local conventions file, which differs between repos', () => {
    expect(kinds('// Unit 3')[0]).toContain('AGENTS.md');
    expect(kinds('// Unit 3', { conventionsFile: 'CLAUDE.md' })[0]).toContain('CLAUDE.md');
  });

  it('reports once per comment, not once per probe', () => {
    expect(run('// Unit 9 §3.1, review response 2, #426, at oss@659b564e')).toHaveLength(1);
  });

  it('exempts a whole comment by pattern, for a generated banner', () => {
    const banner = '// Generated from the Unit 8 schema — do not edit';
    expect(run(banner)).toHaveLength(1);
    expect(run(banner, { allowPatterns: ['^ Generated from'] })).toEqual([]);
  });

  it('switches off one probe where a package has a standing reason', () => {
    const code = '// ratified 2026-09-24';
    expect(run(code)).toHaveLength(1);
    expect(run(code, { disableProbes: ['a dated decision'] })).toEqual([]);
  });

  it('reads block comments and trailing comments, not just leading line ones', () => {
    expect(run('/* Unit 4 owns this */')).toHaveLength(1);
    expect(run('const x = 1; // task 4.2 added it')).toHaveLength(1);
  });
});
