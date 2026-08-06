// CONTRIBUTING.md ("Checks that gate `main`") lists the status checks branch
// protection matches on. Protection matches by NAME, so a renamed job does not
// fail — it stops being produced, protection goes on waiting for a name nothing
// emits, and the check is silently no longer required. That failure is invisible
// in a diff and invisible in a green run, which is why the table is read here
// and driven against the workflows rather than being trusted.
//
// What this cannot see is repository settings: whether each name is actually
// configured as required lives outside the tree. This pins the half that is in
// the tree — that every name in the table still belongs to a real job.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');

const readWorkflow = (file) => readFileSync(join(WORKFLOWS, file), 'utf8');

// A job's `name:` sits at four spaces (`jobs:` → job key at two → its keys at
// four). A step's is deeper and carries a `- `, so this matches job names only.
const JOB_NAME = /^ {4}name: (.+)$/gm;

// One `${{ matrix.<key> }}` in a job name, which is how a matrix job produces
// one check per value. Anything more elaborate is not in use and would show up
// here as an unexpanded name that matches nothing in the table.
const MATRIX_REF = /\$\{\{\s*matrix\.([a-zA-Z0-9_-]+)\s*\}\}/;

function matrixValues(source, key) {
  const inline = new RegExp(`^\\s*${key}: \\[(.+)\\]$`, 'm').exec(source);
  if (inline === null) return [];
  return inline[1].split(',').map((value) => value.trim().replace(/^['"]|['"]$/g, ''));
}

// Every check name a workflow can emit, with matrix jobs expanded to the names
// GitHub actually reports.
function checkNames(file) {
  const source = readWorkflow(file);
  const names = [];
  for (const [, rawName] of source.matchAll(JOB_NAME)) {
    const name = rawName.trim();
    const ref = MATRIX_REF.exec(name);
    if (ref === null) {
      names.push(name);
      continue;
    }
    for (const value of matrixValues(source, ref[1])) {
      names.push(name.replace(MATRIX_REF, value));
    }
  }
  return names;
}

// The table itself: | `Check name` | `workflow.yml` |
function requiredChecks() {
  const contributing = readFileSync(join(REPO_ROOT, 'CONTRIBUTING.md'), 'utf8');
  const section = /## Pull requests[\s\S]*?### Checks that gate `main`([\s\S]*?)```bash/.exec(
    contributing,
  );
  expect(section).not.toBeNull();
  return [...section[1].matchAll(/^\| `([^`]+)`\s*\| `([^`]+)`\s*\|$/gm)].map(
    ([, check, file]) => ({
      check,
      file,
    }),
  );
}

describe('the required-check table in CONTRIBUTING.md', () => {
  const rows = requiredChecks();

  // A table that parsed to nothing would satisfy every per-row assertion below
  // without checking anything, so pin the count first. The three CI jobs, the
  // audit, and CodeQL's two matrix legs.
  it('parses, and covers every gate the table is supposed to list', () => {
    expect(rows).toHaveLength(6);
    expect(rows.map((row) => row.file)).toEqual(
      expect.arrayContaining(['ci.yml', 'audit.yml', 'codeql.yml']),
    );
  });

  it.each(rows)('$check is a real job in $file', ({ check, file }) => {
    expect(checkNames(file)).toContain(check);
  });

  // The matrix expander is load-bearing for the two CodeQL rows: without it
  // they would read as the literal `CodeQL (${{ matrix.language }})` and match
  // nothing. Pin that it expands rather than trusting the rows above, which
  // would also pass if the table itself drifted to the unexpanded spelling.
  it('expands a matrix job into the names GitHub reports', () => {
    const names = checkNames('codeql.yml');
    expect(names).toContain('CodeQL (javascript-typescript)');
    expect(names).toContain('CodeQL (actions)');
    expect(names.some((name) => name.includes('matrix.'))).toBe(false);
  });

  // The audit workflow's second job reports a check too, and it is deliberately
  // NOT required — it only ever runs on the schedule, so requiring it would
  // block every PR on a check that is permanently skipped there.
  it('does not require the scheduled advisory-reporting job', () => {
    expect(checkNames('audit.yml')).toContain('File advisory issue (scheduled runs)');
    expect(rows.map((row) => row.check)).not.toContain('File advisory issue (scheduled runs)');
  });
});

describe('the workflows behind those checks', () => {
  // `Dependency audit` and the CodeQL legs are only "on every PR" if neither
  // workflow filters `pull_request` by base branch. A `branches:` filter there
  // excludes a stacked PR entirely — no run, no check — and for a required
  // check that means a PR that can never satisfy it.
  // The block ends at the next sibling KEY, and a `#` comment is not one — an
  // end-of-block test that stopped at the first two-space non-space character
  // would end at a comment line instead, so a `branches:` filter written below
  // one would sit outside the captured block and be missed.
  it.each(['audit.yml', 'codeql.yml'])('%s runs on every PR, whatever its base', (file) => {
    const source = readWorkflow(file);
    const trigger = /^ {2}pull_request:[^\S\n]*$([\s\S]*?)^ {2}[^\s#]/m.exec(source);
    expect(trigger).not.toBeNull();
    expect(trigger[1]).not.toMatch(/^\s*branches:/m);
  });

  it('both run daily or weekly as well as on PRs', () => {
    expect(readWorkflow('audit.yml')).toMatch(/^\s*- cron: '[^']+'$/m);
    expect(readWorkflow('codeql.yml')).toMatch(/^\s*- cron: '[^']+'$/m);
  });

  // Code scanning cannot upload results without it, so the analysis would run
  // and report nothing.
  it('codeql.yml grants security-events: write', () => {
    expect(readWorkflow('codeql.yml')).toMatch(/^\s*security-events: write$/m);
  });
});
