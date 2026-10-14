// The line readers in helpers/workflow.js that the other workflow suites lean on
// for where a job or a step begins and ends. Each is asserted here against text
// built for the purpose, so a regression in a reader is reported as one rather
// than as a guard that goes on passing over a block it read short. The decoded
// reader the release guards use has its own suite, in workflow-yaml.test.js.

import { describe, expect, it } from 'vitest';

import { blockScalarLines, blockScalarText, jobBlock, steps } from './helpers/workflow.js';

describe('jobBlock', () => {
  const WORKFLOW = [
    'jobs:',
    '  first:',
    '    runs-on: ubuntu-24.04',
    '    steps:',
    '      - name: Before',
    '        run: echo before',
    '  # a comment at job-key indentation, between two steps of the same job',
    '      - name: After',
    '        run: echo after',
    '  second:',
    '    runs-on: ubuntu-24.04',
    '    steps:',
    '      - name: Other',
    '        run: echo other',
    '',
  ].join('\n');

  // A comment may sit at any column. One at the job-key column is not the next
  // job, and ending the body there hides every step below it from each check.
  it('does not end a job at a comment indented like a job id', () => {
    const body = jobBlock(WORKFLOW, 'first');

    expect(body).toContain('name: After');
    expect(body).not.toContain('name: Other');
  });
});

describe('steps', () => {
  // The item's first key may sit on the next line; the marker is still a step.
  it('splits on a bare list marker as well as on `- `', () => {
    const job = [
      '      - name: One',
      '        run: echo one',
      '      -',
      '        name: Two',
      '        run: echo two',
      '',
    ].join('\n');

    expect(steps(job)).toHaveLength(2);
  });
});

describe('blockScalarText and blockScalarLines', () => {
  const STEP = [
    'name: Push',
    '        run: |',
    '          echo real',
    '          echo again',
    '',
  ].join('\n');

  it('read the block scalar under the key', () => {
    expect(blockScalarText(STEP, 'run')).toBe('echo real\necho again');
    expect(blockScalarLines(STEP, 'run')).toEqual(['echo real', 'echo again']);
  });

  // The column-pinning option these once took is gone with the readers that used
  // it. A caller still passing one must find out, not be read as if it had not.
  it('refuse a third argument rather than ignore it', () => {
    expect(() => blockScalarText(STEP, 'run', { indent: 8 })).toThrow(/takes no options/);
    expect(() => blockScalarLines(STEP, 'run', { indent: 8 })).toThrow(/takes no options/);
  });
});
