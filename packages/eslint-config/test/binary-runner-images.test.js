// The matrix-leg reader in helpers/runner-images.js, asserted against text built
// for the purpose, plus the one property neither binary fan-out can state about
// itself: that the two agree.
//
// The reader's own refusals are the half a suite over the real workflows cannot
// reach. Every case in build-binaries-wait-for-ci.test.js and
// release-binaries-integrity.test.js hands it a well-formed matrix, so each
// refusal in it is free to rot into a no-op without a single test noticing —
// measured, before this file existed, by weakening two of them in place and
// watching both suites stay green.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { expectSupportedRunnerImages, matrixLegs } from './helpers/runner-images.js';
import { parseWorkflow } from './helpers/workflow-yaml.js';

/** A one-job workflow whose `build` job fans out over the given matrix legs. */
const fanOut = (runsOn, ...legs) =>
  parseWorkflow(
    [
      'jobs:',
      '  build:',
      `    runs-on: ${runsOn}`,
      '    strategy:',
      '      matrix:',
      '        include:',
      ...legs.map((leg) => `          - ${leg}`),
      '    steps:',
      '      - run: true',
      '',
    ].join('\n'),
  );

/** The four legs the real fan-outs pin, as a well-formed matrix. */
const SUPPORTED_LEGS = [
  '{ os: macos-15, target: darwin-arm64 }',
  '{ os: ubuntu-24.04, target: linux-x64 }',
  '{ os: ubuntu-24.04-arm, target: linux-arm64 }',
  '{ os: windows-2022, target: win32-x64 }',
];

/** One darwin-arm64 leg on the given label, which is what most cases vary. */
const darwinOn = (label) => fanOut('${{ matrix.os }}', `{ os: ${label}, target: darwin-arm64 }`);

const workflowAt = (file) =>
  parseWorkflow(readFileSync(join(REPO_ROOT, '.github', 'workflows', file), 'utf8'));

/** A fan-out's `target: image` map, which is the shape the two are compared in. */
const imagesByTarget = (file) =>
  Object.fromEntries(matrixLegs(workflowAt(file), 'build').map((leg) => [leg.target, leg.image]));

describe('the matrix-leg reader', () => {
  it('reads every leg, through the matrix key the job names', () => {
    expect(matrixLegs(fanOut('${{ matrix.os }}', ...SUPPORTED_LEGS), 'build')).toEqual([
      { target: 'darwin-arm64', image: 'macos-15' },
      { target: 'linux-x64', image: 'ubuntu-24.04' },
      { target: 'linux-arm64', image: 'ubuntu-24.04-arm' },
      { target: 'win32-x64', image: 'windows-2022' },
    ]);
  });

  // Whitespace inside `${{ }}` is optional to GitHub, and the key is whatever
  // the job names: a reader pinned to one spelling of one key reddens a
  // workflow the runner is happy with, and does it with a message about the
  // matrix rather than about the spelling.
  it.each([
    ['no spaces inside the braces', '${{matrix.os}}', '{ os: macos-15, target: darwin-arm64 }'],
    ['a key other than `os`', '${{ matrix.image }}', '{ image: macos-15, target: darwin-arm64 }'],
  ])('accepts %s', (_label, runsOn, leg) => {
    expect(matrixLegs(fanOut(runsOn, leg), 'build')).toEqual([
      { target: 'darwin-arm64', image: 'macos-15' },
    ]);
  });

  describe('refuses a matrix it cannot answer about', () => {
    it.each([
      [
        'a job that names its runner directly',
        () => fanOut('macos-15', ...SUPPORTED_LEGS),
        /does not take its runner from the matrix/,
      ],
      [
        'a key the legs do not carry',
        () => fanOut('${{ matrix.image }}', '{ os: macos-15, target: darwin-arm64 }'),
        /declares no `image:` label/,
      ],
      [
        'a leg that is not a mapping',
        () => fanOut('${{ matrix.os }}', 'macos-15'),
        /leg that is not a mapping/,
      ],
      [
        'a leg with no target',
        () => fanOut('${{ matrix.os }}', '{ os: macos-15 }'),
        /leg declaring no `target:`/,
      ],
      [
        'a leg with no label',
        () => fanOut('${{ matrix.os }}', '{ target: darwin-arm64 }'),
        /declares no `os:` label/,
      ],
      [
        'a target spelled twice',
        () =>
          fanOut(
            '${{ matrix.os }}',
            '{ os: macos-15, target: darwin-arm64 }',
            '{ os: macos-26, target: darwin-arm64 }',
          ),
        /spells a target twice/,
      ],
      ['an empty include list', () => fanOut('${{ matrix.os }}'), /declares no include list/],
    ])('%s', (_label, build, message) => {
      // The thunk READS the matrix: `fanOut` alone only parses, and a case that
      // never reached the reader would report "expected [Function] to throw"
      // for the wrong reason.
      expect(() => matrixLegs(build(), 'build')).toThrow(message);
    });

    it.each([
      [
        'a job with no strategy',
        ['jobs:', '  build:', '    runs-on: ${{ matrix.os }}', '    steps:', '      - run: true'],
        /declares no strategy block/,
      ],
      [
        'a strategy with no matrix',
        [
          'jobs:',
          '  build:',
          '    runs-on: ${{ matrix.os }}',
          '    strategy:',
          '      fail-fast: false',
          '    steps:',
          '      - run: true',
        ],
        /declares no matrix/,
      ],
    ])('%s', (_label, lines, message) => {
      expect(() => matrixLegs(parseWorkflow(`${lines.join('\n')}\n`), 'build')).toThrow(message);
    });
  });
});

describe('the runner image assertion', () => {
  it('passes the four legs the fan-outs pin', () => {
    expect(() =>
      expectSupportedRunnerImages(fanOut('${{ matrix.os }}', ...SUPPORTED_LEGS), 'build'),
    ).not.toThrow();
  });

  // A retired label, whatever case it is written in: GitHub matches runner
  // labels case-insensitively, so `MacOS-14` reaches the retired image exactly
  // as `macos-14` does.
  it.each(['macos-14', 'MacOS-14', 'macos-14-xlarge', 'macos-13'])(
    'refuses the retired label %s',
    (label) => {
      expect(() => expectSupportedRunnerImages(darwinOn(label), 'build')).toThrow(
        /a retired runner image/,
      );
    },
  );

  // The half the deny list cannot ask. Every label here is one GitHub still
  // serves, and none of them is the arm64 macOS image a `darwin-arm64` archive
  // has to be built on — `-large` and `-intel` are the x64 images, and
  // `-latest` moves under the channel rather than being pinned.
  it.each(['macos-15-large', 'macos-15-intel', 'macos-latest', 'ubuntu-24.04'])(
    'refuses %s for the darwin-arm64 target',
    (label) => {
      expect(() => expectSupportedRunnerImages(darwinOn(label), 'build')).toThrow(
        /not the explicitly pinned image that target needs/,
      );
    },
  );

  it('refuses a target no shape is declared for, rather than passing it through', () => {
    expect(() =>
      expectSupportedRunnerImages(
        fanOut('${{ matrix.os }}', '{ os: ubuntu-24.04, target: linux-riscv64 }'),
        'build',
      ),
    ).toThrow(/no runner image shape is declared/);
  });
});

// The two fan-outs are maintained by hand in two files. build-binaries.yml is
// what a pull request builds and smoke-tests; release-binaries.yml is what a
// `bin-v*` tag actually ships from, and it has no pull_request trigger — so an
// image pinned in one and not the other first runs on a real release, after
// four runners have already spent.
describe('the two binary fan-outs', () => {
  it('builds each target on the same runner image', () => {
    const build = imagesByTarget('build-binaries.yml');
    // The positive control: two empty maps are equal, and would say nothing.
    expect(Object.keys(build), 'build-binaries.yml declares no fan-out legs').not.toHaveLength(0);
    expect(imagesByTarget('release-binaries.yml')).toEqual(build);
  });
});
