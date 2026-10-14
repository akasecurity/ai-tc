// The guard on this repository's own root `.akaignore`, run once per walker
// that reads it: `collectFiles` in packages/local-ops (the folder scans) and
// `walkTree` in packages/scanner (`/aka:scan` and the worktree scan). The two
// walkers have different floors, so each suite drives its own.
//
// What it pins is the SKIPPED SET, exactly. The tracked tree is copied into a
// scratch root, gitignored build output and local captures are planted beside
// it, and the walker runs twice: once with no `.akaignore` (the walker's own
// floors only) and once with the real file. The difference must equal what
// `intendedSkip` names — so a pattern that grows past its intent (a `*.md`, a
// `src/bench/`) goes red, and so does one that stops covering what it should.
// Each entry must also change that difference on its own, so a typo'd or
// redundant line cannot sit in the file looking like coverage.
//
// It sits at the repo root because two packages need it and a package wall
// blocks the import, the reason `remove-tree.ts` lives here. What it reads is
// every tracked path, so both packages' turbo.json hash the repository root,
// minus the dependency tree, git's own store and the gitignored build and test
// output, which an explicit `$TURBO_ROOT$` glob does not drop on its own. Left
// in, a reinstall or another package's coverage run would move the hash.
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTrees } from './remove-tree.ts';
import { declaredTestInputs, turboRootInput } from './turbo-inputs.ts';

export const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

const SRC_FIXTURE_DIRS = [
  'packages/detections/src/egress/fixtures/',
  'packages/detections/src/posture/fixtures/',
  'packages/persistence/src/test-fixtures/',
];

// The plugins' fixture trees hold recordings of real sessions and stay
// visible to a scan, all but the one tree built from a published contract.
const RECORDING_DIRS = [
  'plugins/copilot/test/fixtures/cli/',
  'plugins/codex/test/fixtures/hooks/',
  'plugins/claude-code/test/fixtures/',
  'plugins/browser-extension/test/fixtures/',
];
const CONSTRUCTED_PLUGIN_FIXTURES = 'plugins/copilot/test/fixtures/vscode-provisional/';

const BUILD_OUTPUT = [
  'plugins/claude-code/scripts/',
  'plugins/codex/scripts/',
  'plugins/antigravity/scripts/',
  'plugins/copilot/scripts/',
  'plugins/claude-code/hooks/engine.js',
  'plugins/browser-extension/native-host/',
  'cli/native-host/',
  'cli/extension/',
  'cli/web-ui/',
  'cli/sea-dist/',
  'cli/dist-sea/',
];

/** Whether the repository means to skip `rel` (a posix path from the root). */
export function intendedSkip(rel: string): boolean {
  if (rel.startsWith('rules/')) return true;
  if (SRC_FIXTURE_DIRS.some((dir) => rel.startsWith(dir))) return true;
  if (BUILD_OUTPUT.some((out) => (out.endsWith('/') ? rel.startsWith(out) : rel === out))) {
    return true;
  }
  if (rel.endsWith('.tsbuildinfo')) return true;
  if (/^packages\/[^/]+\/bench\//.test(rel)) return true;
  // Test trees at a package's root (or the repo's), and tests beside source.
  if (/^(?:(?:packages|tools)\/[^/]+\/|cli\/|web-ui\/)?test\//.test(rel)) return true;
  if (/^packages\/[^/]+\/src\/.*\.test\.ts$/.test(rel)) return true;
  // A plugin's test tree, all but its fixture recordings.
  if (/^plugins\/[^/]+\/test\//.test(rel)) {
    return (
      !/^plugins\/[^/]+\/test\/fixtures\//.test(rel) || rel.startsWith(CONSTRUCTED_PLUGIN_FIXTURES)
    );
  }
  return false;
}

// Gitignored files a clean checkout does not have, planted so the entries that
// cover them are exercised. Each is skipped or kept per `intendedSkip`.
const PLANTED = [
  // Build output.
  ...BUILD_OUTPUT.map((out) => (out.endsWith('/') ? `${out}planted.js` : out)),
  'web-ui/tsconfig.tsbuildinfo',
  'packages/schema/tsconfig.tsbuildinfo',
  // Local captures and credentials that must stay visible.
  'plugins/browser-extension/test/fixtures/claude-ai/capture.har',
  'plugins/browser-extension/test/fixtures/claude-ai/capture.raw.json',
  'plugins/copilot/test/fixtures/cli/new-recording.json',
  'plugins/antigravity/test/fixtures/new-recording.json',
  // A test file under a fixture tree is still kept: the recording rule wins.
  'plugins/codex/test/fixtures/hooks/planted.test.ts',
  // Tests elsewhere than a package root, or beside source in a form the
  // colocated entry does not name, stay scanned.
  'packages/scanner/src/planted.test.tsx',
  'docs-site/test/planted.ts',
  'cli/src/test/planted.ts',
  'web-ui/app/test/planted.ts',
  'web-ui/.env.local',
  // Same-named directories outside the locations each entry is anchored to.
  'packages/scanner/src/bench/planted.ts',
  'packages/local-ops/src/test/fixtures/planted.ts',
  'skills/write-detection-rule/rules/planted.md',
  'cli/src/native-host/planted.ts',
];

const toPosix = (p: string): string => p.split(sep).join('/');

/** The non-comment, non-blank lines of an `.akaignore`. */
function entriesOf(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));
}

/** Walks `root` and returns every absolute file path the walker yields. */
export type RepoWalker = (root: string, scratch: string) => Iterable<string>;

export function describeRepoAkaignore(walkerName: string, packageDir: string, walk: RepoWalker) {
  describe(`the repository .akaignore under ${walkerName}`, () => {
    const scratchDirs: string[] = [];
    let root: string;
    let home: string;
    let akaignore: string;
    let tracked: string[];
    let baseline: Set<string>;
    let full: Set<string>;

    const walkWith = (ignoreText: string | null): Set<string> => {
      const file = join(root, '.akaignore');
      writeFileSync(file, ignoreText ?? '');
      const yielded = new Set<string>();
      for (const path of walk(root, home)) yielded.add(toPosix(relative(root, path)));
      yielded.delete('.akaignore');
      return yielded;
    };

    beforeAll(() => {
      root = mkdtempSync(join(tmpdir(), 'aka-repo-akaignore-'));
      home = mkdtempSync(join(tmpdir(), 'aka-repo-akaignore-home-'));
      scratchDirs.push(root, home);
      akaignore = readFileSync(join(REPO_ROOT, '.akaignore'), 'utf8');

      tracked = execFileSync('git', ['ls-files', '-z'], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      })
        .split('\0')
        .filter((file) => file !== '' && file !== '.akaignore');
      for (const file of tracked) {
        const from = join(REPO_ROOT, ...file.split('/'));
        try {
          // A symlink is never yielded by either walker, and a file deleted in
          // the working tree is still listed until staged.
          if (!lstatSync(from).isFile()) continue;
        } catch {
          continue;
        }
        const to = join(root, ...file.split('/'));
        mkdirSync(dirname(to), { recursive: true });
        copyFileSync(from, to);
      }
      for (const file of PLANTED) {
        const to = join(root, ...file.split('/'));
        mkdirSync(dirname(to), { recursive: true });
        writeFileSync(to, 'placeholder\n');
      }

      baseline = walkWith(null);
      full = walkWith(akaignore);
    }, 120_000);

    afterAll(() => {
      removeTrees(scratchDirs);
    });

    it('skips exactly the files the repository means to skip', () => {
      const skipped = [...baseline].filter((file) => !full.has(file)).sort();
      const intended = [...baseline].filter(intendedSkip).sort();
      // Reported as two lists so a failure names the direction it went wrong in.
      expect(
        skipped.filter((file) => !intendedSkip(file)),
        'skipped although nothing says it should be',
      ).toEqual([]);
      expect(
        intended.filter((file) => full.has(file)),
        'meant to be skipped and still read',
      ).toEqual([]);
      expect(intended.length).toBeGreaterThan(0);
    });

    it('drives every family the skip set and its exceptions name', () => {
      // Without a file in each, the assertion above holds for that family
      // whatever the patterns say.
      const families = [
        'rules/',
        ...SRC_FIXTURE_DIRS,
        'test/fixtures/',
        ...RECORDING_DIRS,
        CONSTRUCTED_PLUGIN_FIXTURES,
        'test/setup/',
        'cli/test/',
        'web-ui/test/',
        'packages/persistence/test/',
        'tools/installer/test/',
        'plugins/claude-code/test/hooks/',
        'packages/local-ops/src/self-exec.test.ts',
        'plugins/browser-extension/scripts/',
      ];
      expect(families.filter((dir) => ![...baseline].some((file) => file.startsWith(dir)))).toEqual(
        [],
      );
      expect(PLANTED.filter((file) => !baseline.has(file))).toEqual([]);
    });

    it('has no entry that changes nothing', () => {
      const entries = entriesOf(akaignore);
      expect(entries.length).toBeGreaterThan(0);
      const inert = entries.filter((entry, index) => {
        const without = entriesOf(akaignore).filter((_, other) => other !== index);
        const yielded = walkWith(without.join('\n'));
        return yielded.size === full.size && [...yielded].every((file) => full.has(file));
      });
      walkWith(akaignore);
      expect(inert).toEqual([]);
    }, 120_000);

    it("is hashed into this package's test task", () => {
      // The suite reads every tracked path, so an add anywhere has to move the
      // hash or turbo replays a cached pass.
      const inputs = declaredTestInputs(packageDir);
      expect(inputs).toContain('$TURBO_DEFAULT$');
      expect(inputs).toContain(turboRootInput('**'));
      // An explicit root glob ignores .gitignore, so each of these has to be
      // excluded by name or the hash follows install and build state.
      for (const dir of ['.git', '**/node_modules', '**/.turbo', '**/coverage', '**/dist']) {
        expect(inputs, dir).toContain(`!${turboRootInput(`${dir}/**`)}`);
      }
    });
  });
}
