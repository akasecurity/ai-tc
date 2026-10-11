// The readers in helpers/workflow.js that the release guards lean on for what a
// token or a key can reach. Each is asserted here against text built for the
// purpose, so a regression in a reader is reported as one rather than as a guard
// that goes on passing over a mapping it read short.

import { describe, expect, it } from 'vitest';

import {
  blockScalarText,
  expressionsIn,
  jobBlock,
  linesOutsideBlockScalars,
  mappingOf,
  steps,
  withMapping,
} from './helpers/workflow.js';

const JOB = [
  '    runs-on: ubuntu-24.04',
  '    permissions:',
  '      contents: read',
  '',
  '      actions: write # a comment',
  '    env:',
  '      FIRST: one',
  '    steps:',
  '      - name: Step',
  '        env:',
  '          INNER: two',
  '        with:',
  '          client-id: ${{ vars.CLIENT }}',
  '',
  '          owner: akasecurity',
  '',
].join('\n');

describe('mappingOf', () => {
  // YAML carries on past a blank line, so an entry written after one is part of
  // the mapping GitHub evaluates. A reader that stopped at the gap reported
  // `{ contents: 'read' }` for a job that grants `actions: write` as well.
  it('reads past a blank line inside the mapping', () => {
    expect(mappingOf(JOB, 'permissions', { indent: 4 })).toEqual({
      contents: 'read',
      actions: 'write',
    });
  });

  it('stops at the first non-blank line that is not indented past the key', () => {
    expect(mappingOf(JOB, 'env', { indent: 4 })).toEqual({ FIRST: 'one' });
  });

  // A job's own `env:` and a step's carry the same key, and only the column tells
  // them apart.
  it('pins the opener to a column when asked', () => {
    expect(mappingOf(JOB, 'env', { indent: 4 })).toEqual({ FIRST: 'one' });
    expect(mappingOf(JOB, 'env', { indent: 8 })).toEqual({ INNER: 'two' });
  });

  it('strips a trailing YAML comment from a value and keeps an expression whole', () => {
    expect(mappingOf(JOB, 'permissions', { indent: 4 }).actions).toBe('write');
    expect(withMapping(JOB)['client-id']).toBe('${{ vars.CLIENT }}');
  });

  // Each of these is a shape the entry reader would otherwise flatten into
  // siblings and report as a mapping other than the one in the file.
  it('refuses an entry that opens a nested mapping or a block scalar', () => {
    for (const [label, lines] of [
      ['a nested mapping', ['    env:', '      OUTER:', '        INNER: x']],
      ['a nested mapping with a trailing space', ['    env:', '      OUTER: ', '        INNER: x']],
      ['a block scalar', ['    env:', '      SCRIPT: |', '        echo: hi']],
      ['a folded scalar', ['    env:', '      TEXT: >-', '        words: here']],
    ]) {
      expect(() => mappingOf(lines.join('\n'), 'env', { indent: 4 }), label).toThrow();
    }
  });

  // An empty block scalar has no body for the column check to trip on, so the
  // header itself is what has to be refused.
  it('refuses a block scalar header even when its body is empty', () => {
    const text = ['    env:', '      EMPTY: |', '      NEXT: 1'].join('\n');

    expect(() => mappingOf(text, 'env', { indent: 4 })).toThrow(/opens a block scalar/);
  });

  it('refuses an entry at a different column from the first', () => {
    const ragged = ['    env:', '      ONE: 1', '        TWO: 2'].join('\n');

    expect(() => mappingOf(ragged, 'env', { indent: 4 })).toThrow(/not at the column/);
  });

  // A comment is legal anywhere in a mapping and does not end it; an entry
  // written after one belongs to the mapping.
  it('reads past a comment line, including one at the key column', () => {
    const text = ['    env:', '      ONE: 1', '# a comment at column 0', '      TWO: 2'].join('\n');

    expect(mappingOf(text, 'env', { indent: 4 })).toEqual({ ONE: '1', TWO: '2' });
  });

  // `steps()` strips the list marker, so the first key of a slice sits at column
  // 0 while its siblings sit at 8: a mapping opening there cannot be told from
  // them, and is refused rather than read with the siblings folded in.
  it('refuses a mapping that opens a step slice', () => {
    const [slice] = steps(
      ['      - with:', '          owner: o', '        uses: actions/x@v1', ''].join('\n'),
    );

    expect(() => mappingOf(slice, 'with')).toThrow(/first key of a step slice/);
  });

  it('refuses a source with no such mapping', () => {
    expect(() => mappingOf(JOB, 'strategy')).toThrow(/no `strategy:` mapping/);
  });
});

describe('expressionsIn', () => {
  it('reads every expression in order', () => {
    expect(expressionsIn('a ${{ one }} b ${{ two.three }} c')).toEqual([
      '${{ one }}',
      '${{ two.three }}',
    ]);
  });

  // A lazy `}}` match ends this expression inside the string and leaves
  // `secrets.KEY` outside every expression it reports.
  it('does not end an expression at a `}}` inside a string literal', () => {
    const text = "x: ${{ format('}}', secrets.KEY) }}";

    expect(expressionsIn(text)).toEqual(["${{ format('}}', secrets.KEY) }}"]);
  });

  it('treats a doubled quote as an escape rather than the end of the string', () => {
    const text = "${{ format('it''s }}', secrets.KEY) }} tail";

    expect(expressionsIn(text)).toEqual(["${{ format('it''s }}', secrets.KEY) }}"]);
  });

  // The reason the guards read the file's own bytes: GitHub substitutes inside a
  // block scalar, so a `#` line there is still program text.
  it('finds an expression on a line that starts with a hash', () => {
    const script = ['run: |', '  # ${{ secrets.KEY }}', '  echo hi'].join('\n');

    expect(expressionsIn(script)).toEqual(['${{ secrets.KEY }}']);
  });

  it('reports an unterminated expression to the end of the text rather than dropping it', () => {
    expect(expressionsIn('before ${{ secrets.KEY')).toEqual(['${{ secrets.KEY']);
  });

  it('finds nothing in text with no expression', () => {
    expect(expressionsIn('plain text, no expression')).toEqual([]);
  });
});

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

describe('blockScalarText', () => {
  // The decoy: a `run: |` that is TEXT inside another key's block scalar, ahead
  // of the real one. Taking the first opener reads a script the runner never runs.
  const STEP = [
    'name: Push',
    '        env:',
    '          NOTES: |',
    '            run: |',
    '              echo decoy',
    '        run: |',
    '          echo real',
    '',
  ].join('\n');

  it('takes the first opener when the column is not pinned', () => {
    expect(blockScalarText(STEP, 'run')).toBe('echo decoy');
  });

  it('takes only an opener at the pinned column', () => {
    expect(blockScalarText(STEP, 'run', { indent: 8 })).toBe('echo real');
  });
});

describe('linesOutsideBlockScalars', () => {
  it('drops the body of a block scalar and keeps the lines around it', () => {
    const text = [
      '      - name: A',
      '        run: |',
      '          secrets: not a key',
      '          echo "unbalanced',
      '        env:',
      '          K: v',
    ].join('\n');

    expect(linesOutsideBlockScalars(text)).toEqual([
      '      - name: A',
      '        run: |',
      '        env:',
      '          K: v',
    ]);
  });

  it('keys a block scalar to the column of its own key, past list markers', () => {
    const text = ['      - run: |', '          body line', '        name: after'].join('\n');

    expect(linesOutsideBlockScalars(text)).toEqual(['      - run: |', '        name: after']);
  });
});
