// The parsed workflow reader in helpers/workflow-yaml.js, asserted against text
// built for the purpose. Each case is a spelling YAML allows and a line reader
// would have to anticipate: the reader is only worth sharing if every one of them
// decodes to the same structure as the plain spelling, and if what it cannot
// decode is refused rather than read short.

import { describe, expect, it, vi } from 'vitest';
import { Alias, parseDocument } from 'yaml';

import {
  envOf,
  expressionsIn,
  expressionsOf,
  hasKey,
  ifOf,
  inputLines,
  inputsOf,
  jobIds,
  jobOf,
  keysIn,
  needsOf,
  parseWorkflow,
  scriptOf,
  scriptsOf,
  stepIndex,
  stepNamed,
  stepsOf,
  stringsIn,
  usesIndex,
  usesOf,
  writeScopes,
} from './helpers/workflow-yaml.js';

/** A workflow around the given job lines, indented as a job body. */
const workflowWith = (...lines) => ['jobs:', '  job:', ...lines, ''].join('\n');

/** The decoded steps of a one-job workflow whose job body is the given lines. */
const stepsFrom = (...lines) =>
  stepsOf(
    jobOf(parseWorkflow(workflowWith('    runs-on: ubuntu-24.04', '    steps:', ...lines)), 'job'),
  );

describe('parseWorkflow', () => {
  // The case the line reader could only forbid: a double-quoted scalar decodes
  // its escapes before an expression in it is read, so this is the key read in
  // full and contains no `${{` for a text match to find.
  it('decodes an escaped dollar, so the expression it spells is found', () => {
    const [step] = stepsFrom(
      '      - name: Mint',
      '        with:',
      '          private-key: "\\x24{{ secrets.KEY }}"',
      '          again: "\\u0024{{ secrets.KEY }}"',
    );

    expect(inputsOf(step)['private-key']).toBe('${{ secrets.KEY }}');
    expect(inputsOf(step).again).toBe('${{ secrets.KEY }}');
    expect(expressionsOf(step)).toEqual(['${{ secrets.KEY }}', '${{ secrets.KEY }}']);
  });

  it('decodes a scalar folded across lines, and a single-quoted one', () => {
    const [step] = stepsFrom(
      '      - name: Fold',
      '        with:',
      '          joined: "${{ secr\\',
      '            ets.KEY }}"',
      "          quoted: 'it''s'",
      '          plain: ${{ vars.X }}',
    );

    expect(inputsOf(step).joined).toBe('${{ secrets.KEY }}');
    expect(inputsOf(step).quoted).toBe("it's");
    expect(expressionsOf(step)).toEqual(['${{ secrets.KEY }}', '${{ vars.X }}']);
  });

  // A key is a key however it is written: quoted, escaped, or in flow style.
  it('reads quoted, escaped and flow-style keys as the keys they are', () => {
    const steps = stepsFrom(
      '      - name: Quoted',
      '        "env":',
      '          K: v',
      '      - { name: Flow, "uses": a/b@c, if: true }',
      '      - name: Escaped',
      '        "con\\x74inue-on-error": true',
    );

    expect(Object.keys(steps[0])).toEqual(['name', 'env']);
    expect(envOf(steps[0])).toEqual({ K: 'v' });
    expect(steps[1]).toEqual({ name: 'Flow', uses: 'a/b@c', if: true });
    expect(Object.keys(steps[2])).toContain('continue-on-error');
    expect(hasKey(steps, 'continue-on-error')).toBe(true);
  });

  // The decoy a line reader took the first of: a `run:` that is TEXT inside
  // another key's block scalar, written ahead of the real one.
  it('takes the script from the key and not from text that looks like one', () => {
    const [step] = stepsFrom(
      '      - name: Push',
      '        env:',
      '          NOTES: |',
      '            run: |',
      '              echo decoy',
      '        run: |',
      '          echo real',
    );

    expect(scriptOf(step)).toBe('echo real\n');
    expect(envOf(step).NOTES).toBe('run: |\n  echo decoy\n');
  });

  it('keeps a `#` line inside a script and drops a YAML comment', () => {
    const [step] = stepsFrom(
      '      # a YAML comment: ${{ secrets.NOT_READ }}',
      '      - name: Script',
      '        run: |',
      '          # ${{ secrets.READ }}',
      '          echo hi',
    );

    expect(scriptOf(step)).toBe('# ${{ secrets.READ }}\necho hi\n');
    expect(expressionsOf(step)).toEqual(['${{ secrets.READ }}']);
  });

  it('follows an alias to the mapping it names, at every place it is used', () => {
    const workflow = parseWorkflow(
      [
        'jobs:',
        '  first:',
        '    runs-on: x',
        '    permissions: &grants',
        '      contents: read',
        '      packages: write',
        '    steps:',
        '      - run: echo first',
        '  second:',
        '    runs-on: x',
        '    permissions: *grants',
        '    steps:',
        '      - run: echo second',
        '',
      ].join('\n'),
    );

    expect(jobOf(workflow, 'second').permissions).toEqual({ contents: 'read', packages: 'write' });
    expect(writeScopes(jobOf(workflow, 'second').permissions)).toEqual(['packages']);
  });

  it('binds an alias to the last anchor written before it', () => {
    const workflow = parseWorkflow(
      ['a: &x one', 'b: *x', 'c: &x two', 'd: *x', 'jobs: {}', ''].join('\n'),
    );

    expect([workflow.b, workflow.d]).toEqual(['one', 'two']);
  });

  it('resolves an alias written as a mapping key', () => {
    const workflow = parseWorkflow(['k: &k name', '*k : value', 'jobs: {}', ''].join('\n'));

    expect(workflow.name).toBe('value');
  });

  it('resolves an alias to an anchor written on a mapping key', () => {
    const workflow = parseWorkflow(['&k key: 1', 'other: *k', 'jobs: {}', ''].join('\n'));

    expect(workflow.other).toBe('key');
  });

  // From yaml 2.9.1 `Alias.resolve(doc, ctx)` reads `anchors` from the context it is
  // given, and without a context it re-walks the whole document for every alias.
  // The reader resolves aliases from its own table, so the library is not asked.
  it('resolves aliases from its own table, never through the library', () => {
    const resolve = vi.spyOn(Alias.prototype, 'resolve');
    try {
      // Control: the library resolving an alias itself is visible to the spy.
      parseDocument('k: &k name\nv: *k\n').toJS();
      expect(resolve).toHaveBeenCalled();
      resolve.mockClear();

      const workflow = parseWorkflow(['k: &k name', '*k : x', 'v: *k', 'jobs: {}', ''].join('\n'));

      expect(workflow).toMatchObject({ v: 'name', name: 'x' });
      expect(resolve.mock.calls.length, 'calls to Alias#resolve').toBe(0);
    } finally {
      resolve.mockRestore();
    }
  });

  it('reads `on` as a string, as the runner does', () => {
    const workflow = parseWorkflow(['on:', '  push:', '    tags: [v1]', 'jobs: {}', ''].join('\n'));

    expect(Object.keys(workflow)).toEqual(['on', 'jobs']);
  });

  describe('refuses what it cannot decode faithfully', () => {
    const refused = [
      ['a duplicate key', 'jobs:\n  a: { runs-on: x }\n  a: { runs-on: y }\n', /not valid YAML/],
      ['a tab used as indentation', 'jobs:\n\ta: 1\n', /not valid YAML/],
      ['two documents', 'jobs: {}\n---\njobs: {}\n', /exactly one YAML document/],
      ['no document at all', '', /exactly one YAML document/],
      ['an unresolved tag', 'jobs: {}\nname: !custom x\n', /decode differently/],
      ['a %YAML directive', '%YAML 1.1\n---\njobs: {}\n', /`%YAML` directive/],
      ['a %TAG directive', '%TAG !e! tag:example.com,2000:\n---\njobs: {}\n', /`%TAG` directive/],
      [
        'a %TAG !! redefinition that a tag resolves through',
        '%TAG !! tag:example.com,2000:\n---\njobs: !!str x\n',
        /decode differently/,
      ],
      ['a merge key', 'base: &b { x: 1 }\njobs:\n  a:\n    <<: *b\n', /merge key/],
      ['a quoted merge key', 'base: &b { x: 1 }\njobs:\n  a:\n    "<<": *b\n', /merge key/],
      ['a numeric key', 'jobs:\n  1: { runs-on: x }\n', /not a plain string/],
      ['a boolean key', 'jobs:\n  true: { runs-on: x }\n', /not a plain string/],
      ['a collection key', 'jobs:\n  ? [a, b]\n  : c\n', /not a plain string/],
      ['an alias inside the node it names', 'jobs:\n  a: &x [*x]\n', /node it is inside/],
      ['an alias to no anchor', 'jobs: {}\nname: *nope\n', /names no anchor/],
      ['an alias before its anchor', 'jobs: {}\nname: *x\nother: &x y\n', /names no anchor/],
      ['an alias key that names no anchor', 'jobs: {}\n*nope : v\n', /names no anchor/],
      ['an alias key before its anchor', 'jobs: {}\n*k : v\nk: &k name\n', /names no anchor/],
      ['an alias key that names a number', 'n: &n 1\n*n : v\njobs: {}\n', /not a plain string/],
      ['a top level that is not a mapping', '- a\n- b\n', /not a mapping/],
    ];

    it.each(refused)('%s', (_label, text, message) => {
      expect(() => parseWorkflow(text)).toThrow(message);
    });

    // Only a handle other than `!!` is refused as a directive. Redefining `!!`
    // changes nothing until a tag is written through it, and the warning above is
    // what refuses that.
    it('accepts a %TAG !! redefinition that no tag resolves through', () => {
      expect(() => parseWorkflow('%TAG !! tag:example.com,2000:\n---\njobs: {}\n')).not.toThrow();
    });

    // Doubling alias after alias is the shape that multiplies, and the failure
    // has to be a refusal rather than a run that never ends.
    it('an alias chain that expands past any real workflow', () => {
      const levels = 20;
      const lines = ['l0: &l0 [x, x]'];
      for (let level = 1; level < levels; level += 1) {
        lines.push(`l${level}: &l${level} [*l${level - 1}, *l${level - 1}]`);
      }

      // The refusal names the bound and where it lives: this is the one refusal a
      // legitimate change can reach, and it must not read as a defect in the reader.
      expect(() => parseWorkflow(`${lines.join('\n')}\njobs: {}\n`)).toThrow(
        /more nodes[\s\S]*raise MAX_NODES in helpers\/workflow-yaml\.js/,
      );
    });
  });
});

describe('jobs and steps', () => {
  const WORKFLOW = [
    'jobs:',
    '  build:',
    '    runs-on: ubuntu-24.04',
    '    steps:',
    '      - name: Compile',
    '        run: make',
    '      - name: Test',
    '        uses: actions/x@v1',
    '  call:',
    '    uses: o/r/.github/workflows/w.yml@abc',
    '',
  ].join('\n');

  it('reads a runner job and a caller job as jobs', () => {
    const workflow = parseWorkflow(WORKFLOW);

    expect(jobIds(workflow)).toEqual(['build', 'call']);
    expect(Object.keys(jobOf(workflow, 'call'))).toEqual(['uses']);
  });

  it('refuses a job that is missing, bodiless or stepless', () => {
    const workflow = parseWorkflow(
      ['jobs:', '  empty:', '  nosteps:', '    runs-on: x', '  neither:', '    name: n', ''].join(
        '\n',
      ),
    );

    expect(() => jobOf(workflow, 'absent')).toThrow(/no job `absent`/);
    expect(() => jobOf(workflow, 'empty')).toThrow(/not a mapping/);
    expect(() => jobOf(workflow, 'nosteps')).toThrow(/declares no steps/);
    expect(() => jobOf(workflow, 'neither')).toThrow(/neither a runs-on nor a uses/);
  });

  it('names the one step by name, and refuses a name that is absent or repeated', () => {
    const workflow = parseWorkflow(
      [
        'jobs:',
        '  a:',
        '    runs-on: x',
        '    steps:',
        '      - { name: Once, run: one }',
        '      - { name: Twice, run: two }',
        '  b:',
        '    runs-on: x',
        '    steps:',
        '      - { name: Twice, run: three }',
        '',
      ].join('\n'),
    );

    expect(scriptOf(stepNamed(jobOf(workflow, 'a'), 'Once'))).toBe('one');
    expect(() => stepNamed(jobOf(workflow, 'a'), 'Missing')).toThrow(/no single step/);
    // Unique within a job, repeated across the file: the file-wide read refuses.
    expect(scriptOf(stepNamed(jobOf(workflow, 'a'), 'Twice'))).toBe('two');
    expect(() => stepNamed(workflow, 'Twice')).toThrow(/no single step/);
    expect(scriptOf(stepNamed(workflow, 'Once'))).toBe('one');
  });

  it('gives a step position by name and by uses prefix, once', () => {
    const job = jobOf(parseWorkflow(WORKFLOW), 'build');

    expect(stepIndex(job, 'Test')).toBe(1);
    expect(usesIndex(job, 'actions/x@')).toBe(1);
    expect(() => stepIndex(job, 'Absent')).toThrow(/does not occur exactly once/);
    expect(() => usesIndex(job, 'actions/absent@')).toThrow(/does not occur exactly once/);
  });

  it('reads needs in every shape', () => {
    const needs = (text) =>
      needsOf(
        jobOf(parseWorkflow(`jobs:\n  j:\n    runs-on: x\n${text}    steps: [{ run: x }]\n`), 'j'),
      );

    expect(needs('')).toEqual([]);
    expect(needs('    needs: a\n')).toEqual(['a']);
    expect(needs('    needs: [a, b]\n')).toEqual(['a', 'b']);
    expect(needs('    needs:\n      - a\n      - "b"\n')).toEqual(['a', 'b']);
    expect(() => needs('    needs: { a: 1 }\n')).toThrow(/neither a job id/);
  });

  it('reads a gate as its text, and refuses an absent one', () => {
    const [bare, boolean, absent] = stepsFrom(
      '      - { run: a, if: "github.event_name == \'push\'" }',
      '      - { run: b, if: false }',
      '      - { run: c }',
    );

    expect(ifOf(bare, 'the step')).toBe("github.event_name == 'push'");
    expect(ifOf(boolean, 'the step')).toBe('false');
    expect(() => ifOf(absent, 'the step')).toThrow(/declares no single `if:`/);
  });

  // The runner hands every input and variable to the process as text, so the
  // number 24 and the string "24" are the same input.
  it('reads inputs and environment as text, and refuses a nested value', () => {
    const [step, nested] = stepsFrom(
      '      - uses: actions/x@v1',
      '        with:',
      '          node-version: 24',
      '          fail: true',
      '          quoted: "true"',
      '          empty:',
      '        env:',
      '          A: 1',
      '      - uses: actions/x@v1',
      '        with:',
      '          deeper: { a: b }',
    );

    expect(inputsOf(step)).toEqual({
      'node-version': '24',
      fail: 'true',
      quoted: 'true',
      empty: '',
    });
    expect(envOf(step)).toEqual({ A: '1' });
    expect(() => inputsOf(nested)).toThrow(/not a scalar/);
  });

  it('reads a multi-line input as its non-blank, trimmed lines', () => {
    const [step, folded, empty, absent] = stepsFrom(
      '      - uses: a/b@c',
      '        with:',
      '          files: |',
      '            one',
      '',
      '              two  ',
      '      - uses: a/b@c',
      '        with:',
      '          files: >-',
      '            one',
      '            two',
      '      - uses: a/b@c',
      '        with:',
      '          files: ""',
      '      - uses: a/b@c',
    );

    expect(inputLines(step, 'files')).toEqual(['one', 'two']);
    // A folded scalar is ONE entry containing a space, which is what the action
    // receives and what a glob list must not be allowed to become.
    expect(inputLines(folded, 'files')).toEqual(['one two']);
    expect(() => inputLines(empty, 'files')).toThrow(/declares no entries/);
    expect(() => inputLines(absent, 'files')).toThrow(/declares no `files:` input/);
  });

  it('reads every script of a job, in either form', () => {
    const workflow = parseWorkflow(
      workflowWith(
        '    runs-on: x',
        '    steps:',
        '      - run: echo one',
        '      - uses: a/b@c',
        '      - run: |',
        '          echo two',
      ),
    );

    expect(scriptsOf(jobOf(workflow, 'job'))).toEqual(['echo one', 'echo two\n']);
    expect(scriptsOf(workflow)).toEqual(['echo one', 'echo two\n']);
  });
});

describe('uses', () => {
  // The version a pinned SHA resolves to is written as a comment, so a pin check
  // that read only the decoded value could not see whether it was there.
  it('returns the reference with its trailing comment', () => {
    const [pinned, bare, flow] = stepsFrom(
      '      - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2',
      '      - uses: actions/checkout@v7',
      '      - { uses: "a/b@c" } # not a comment on the value',
    );

    expect(usesOf(pinned)).toBe('actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2');
    expect(usesOf(bare)).toBe('actions/checkout@v7');
    expect(usesOf(flow)).toBe('a/b@c');
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

  it('reports an unterminated expression to the end of the text rather than dropping it', () => {
    expect(expressionsIn('before ${{ secrets.KEY')).toEqual(['${{ secrets.KEY']);
  });

  it('finds nothing in text with no expression', () => {
    expect(expressionsIn('plain text, no expression')).toEqual([]);
  });
});

describe('expressionsOf', () => {
  it('reads keys as well as values, in file order', () => {
    const [step] = stepsFrom(
      '      - name: x',
      '        env:',
      '          "${{ a }}": ${{ b }}',
      '          C: ${{ c }}',
    );

    expect(expressionsOf(step)).toEqual(['${{ a }}', '${{ b }}', '${{ c }}']);
  });
});

describe('keys and strings', () => {
  it('lists every key at every depth, and matches a name case-insensitively', () => {
    const value = { a: { Secrets: 1, list: [{ B: 2 }] } };

    expect(keysIn(value)).toEqual(['a', 'Secrets', 'list', 'B']);
    expect(hasKey(value, 'secrets')).toBe(true);
    expect(hasKey(value, 'b')).toBe(true);
    expect(hasKey(value, 'sec')).toBe(false);
  });

  it('lists keys and string values, and nothing else', () => {
    expect(stringsIn({ a: 'x', b: [1, true, { c: 'y' }], d: null })).toEqual([
      'a',
      'x',
      'b',
      'c',
      'y',
      'd',
    ]);
  });
});

describe('writeScopes', () => {
  // A value that is a quoted string, a flow entry or another case is still the
  // value `write`; what a text match for `: write` could not see is the spelling
  // that puts quotes or a different case around it.
  it.each([
    ['a plain value', 'contents: write'],
    ['a double-quoted value', 'contents: "write"'],
    ['a single-quoted value', "contents: 'write'"],
    ['a differently cased value', 'contents: Write'],
    ['an escaped value', 'contents: "wri\\x74e"'],
    ['a value in a flow mapping', '{ contents: "write" }'],
  ])('finds %s', (_label, spelling) => {
    const block = spelling.startsWith('{') ? spelling : `{ ${spelling} }`;
    const workflow = parseWorkflow(`permissions: ${block}\njobs: {}\n`);

    expect(writeScopes(workflow.permissions)).toEqual(['contents']);
  });

  it('reports the whole-token shorthands and nothing for read', () => {
    expect(writeScopes('write-all')).toEqual(['write-all']);
    expect(writeScopes('read-all')).toEqual([]);
    expect(writeScopes({ contents: 'read', packages: 'none' })).toEqual([]);
    expect(writeScopes(undefined)).toEqual([]);
  });

  it('refuses a value that is neither', () => {
    expect(() => writeScopes(['contents'])).toThrow(/neither a mapping nor a shorthand/);
  });
});
