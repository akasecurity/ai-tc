// A job output in a release workflow is a value that job promises to hand on.
// One nothing reads promises it to nobody, and the comment explaining what it is
// FOR goes on describing a consumer after the consumer is gone. So every job in
// a release workflow that declares `outputs:` has a reader in the same file.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { releaseWorkflows } from './helpers/release-workflows.js';
import { dropComments } from './helpers/workflow.js';

/**
 * The ids of the jobs in a workflow that declare `outputs:`.
 * @param {string} source the workflow text, comments dropped
 * @returns {string[]}
 */
function jobsWithOutputs(source) {
  const jobs = /^jobs:[^\S\n]*$([\s\S]*)$/m.exec(source);
  if (jobs === null) return [];
  const found = [];
  let current;
  for (const line of jobs[1].split('\n')) {
    const job = /^ {2}([A-Za-z_][A-Za-z0-9_-]*):[^\S\n]*$/.exec(line);
    if (job !== null) {
      current = job[1];
      continue;
    }
    if (current !== undefined && /^ {4}outputs:[^\S\n]*$/.test(line)) found.push(current);
  }
  return found;
}

describe('release job outputs', () => {
  it('finds a job that declares outputs (positive control)', () => {
    const fixture = [
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    outputs:',
      '      version: x',
      '  publish:',
      '    needs: build',
      '',
    ].join('\n');
    expect(jobsWithOutputs(fixture)).toEqual(['build']);
  });

  it('reads the release workflows', () => {
    expect(releaseWorkflows().length).toBeGreaterThanOrEqual(5);
  });

  it('declares no job output that nothing in the same workflow reads', () => {
    const unread = [];
    for (const workflow of releaseWorkflows()) {
      const source = dropComments(readFileSync(join(REPO_ROOT, workflow), 'utf8'));
      for (const job of jobsWithOutputs(source)) {
        if (!source.includes(`needs.${job}.outputs.`)) unread.push(`${workflow} :: ${job}`);
      }
    }
    expect(unread, 'these jobs declare outputs that no job in their workflow reads').toEqual([]);
  });
});
