import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { collectFiles } from '../src/fs-scan.ts';

// The repository's own root `.akaignore`, driven through the walker every
// folder scan uses (`aka scan`, the dashboard's Scan page). It pins what this
// repo's ignore file is FOR: deliberate test data and build output are skipped,
// while product source and the browser extension's raw captures — which can
// hold real auth headers — are still read.
//
// Assertions are about which files the walker yields, never about the pattern
// text, so a pattern that is reworded but still right stays green and one that
// is widened past its intent goes red.
//
// turbo hashes this package and the root `.akaignore` into the task, not the
// rest of the tracked tree. A new file landing elsewhere under an ignored name
// (a `src/bench/`, say) is therefore caught the next time either of those
// changes, not by the commit that adds it.

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const MAX_BYTES = 1_000_000;

const SRC_FIXTURE_DIRS = [
  'packages/detections/src/egress/fixtures/',
  'packages/detections/src/posture/fixtures/',
  'packages/persistence/src/test-fixtures/',
];
const EXTENSION_FIXTURES = 'plugins/browser-extension/test/fixtures/';

const toPosix = (p: string): string => p.split(sep).join('/');

function walk(root: string, scratch: string): Set<string> {
  const yielded = new Set<string>();
  // A scratch home, so the protected credential roots name nothing in the repo.
  for (const file of collectFiles(root, { home: scratch, akaHome: join(scratch, '.aka') })) {
    yielded.add(toPosix(relative(root, file.path)));
  }
  return yielded;
}

const scratchDirs: string[] = [];
function scratchDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratchDirs.push(dir);
  return dir;
}

afterAll(() => {
  removeTrees(scratchDirs);
});

describe('the repository .akaignore over the tracked tree', () => {
  let tracked: string[];
  let yielded: Set<string>;

  beforeAll(() => {
    tracked = execFileSync('git', ['ls-files', '-z'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
      .split('\0')
      .filter(Boolean)
      // A file deleted in the working tree is still listed until staged.
      .filter((file) => {
        try {
          return statSync(join(REPO_ROOT, file)).isFile();
        } catch {
          return false;
        }
      });
    yielded = walk(REPO_ROOT, scratchDir('aka-repo-akaignore-'));
  }, 60_000);

  const isTestFile = (file: string): boolean => /\.test\.[cm]?[jt]sx?$/.test(file);
  const isProductSource = (file: string): boolean =>
    (file.includes('/src/') || file.startsWith('web-ui/app/')) &&
    !SRC_FIXTURE_DIRS.some((dir) => file.startsWith(dir)) &&
    !file.includes('/test/') &&
    !file.includes('/bench/') &&
    !isTestFile(file);

  const missing = (files: string[]): string[] => files.filter((file) => !yielded.has(file));
  const present = (files: string[]): string[] => files.filter((file) => yielded.has(file));

  it('still reads every tracked product-source file', () => {
    const source = tracked.filter(
      (file) => isProductSource(file) && statSync(join(REPO_ROOT, file)).size <= MAX_BYTES,
    );
    expect(source.length).toBeGreaterThan(500);
    expect(missing(source)).toEqual([]);
  });

  it("still reads the browser extension's hand-written scripts and fixtures", () => {
    const kept = tracked.filter(
      (file) =>
        file.startsWith('plugins/browser-extension/scripts/') ||
        file.startsWith(EXTENSION_FIXTURES),
    );
    expect(kept.length).toBeGreaterThan(0);
    expect(missing(kept)).toEqual([]);
  });

  it('skips rule examples and fixtures', () => {
    const rules = tracked.filter((file) => file.startsWith('rules/'));
    expect(rules.length).toBeGreaterThan(0);
    expect(present(rules)).toEqual([]);
  });

  it('skips fixture data kept under a package src/', () => {
    const fixtures = tracked.filter((file) => SRC_FIXTURE_DIRS.some((dir) => file.startsWith(dir)));
    for (const dir of SRC_FIXTURE_DIRS) {
      expect(
        fixtures.some((file) => file.startsWith(dir)),
        dir,
      ).toBe(true);
    }
    expect(present(fixtures)).toEqual([]);
  });

  it('skips every test fixture tree but the browser extension’s', () => {
    const fixtures = tracked.filter(
      (file) =>
        (file.startsWith('test/fixtures/') || file.includes('/test/fixtures/')) &&
        !file.startsWith(EXTENSION_FIXTURES),
    );
    expect(fixtures.some((file) => file.startsWith('test/fixtures/'))).toBe(true);
    expect(fixtures.some((file) => file.startsWith('packages/'))).toBe(true);
    expect(fixtures.some((file) => file.startsWith('plugins/'))).toBe(true);
    expect(present(fixtures)).toEqual([]);
  });

  it('skips benchmark suites', () => {
    const bench = tracked.filter((file) => file.includes('/bench/'));
    expect(bench.length).toBeGreaterThan(0);
    expect(present(bench)).toEqual([]);
  });
});

// Build output and raw captures are gitignored, so a clean checkout has none to
// observe. This plants each shape in a scratch root carrying the same
// `.akaignore`, which also proves the ignored-path assertions above are not
// passing on files that simply are not there.
describe('the repository .akaignore over planted gitignored files', () => {
  let yielded: Set<string>;

  const SKIPPED = [
    'plugins/claude-code/scripts/pre-tool-use.js',
    'plugins/codex/scripts/pre-tool-use.js',
    'plugins/antigravity/scripts/pre-tool-use.js',
    'plugins/copilot/scripts/pre-tool-use.js',
    'plugins/browser-extension/native-host/host.js',
    'web-ui/tsconfig.tsbuildinfo',
  ];
  const KEPT = [
    // Controls: product source, including a `native-host/` that is source
    // rather than the extension's build output.
    'packages/plugin-sdk/src/index.ts',
    'plugins/browser-extension/src/native-host/host.ts',
    'plugins/browser-extension/scripts/build.mjs',
    // Raw web-chat captures: real conversations, so they must stay scanned.
    'plugins/browser-extension/test/fixtures/claude-ai/capture.har',
    'plugins/browser-extension/test/fixtures/claude-ai/capture.raw.json',
    // A credential dropped into the working copy.
    'web-ui/.env.local',
  ];

  beforeAll(() => {
    const root = scratchDir('aka-repo-akaignore-planted-');
    copyFileSync(join(REPO_ROOT, '.akaignore'), join(root, '.akaignore'));
    for (const file of [...SKIPPED, ...KEPT]) {
      const path = join(root, ...file.split('/'));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, 'placeholder\n');
    }
    yielded = walk(root, scratchDir('aka-repo-akaignore-home-'));
  });

  it('skips gitignored build output', () => {
    expect(SKIPPED.filter((file) => yielded.has(file))).toEqual([]);
  });

  it('still reads product source, hand-written scripts, raw captures and env files', () => {
    expect(KEPT.filter((file) => !yielded.has(file))).toEqual([]);
  });
});
