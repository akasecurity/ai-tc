import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { buildReport } from '../src/lib.ts';
import {
  compareVersions,
  lockfileImporters,
  lockfileVersions,
  type OverrideReview,
  parseOverrideFloors,
  parseVersion,
  reviewOverrideFloors,
  reviewRootOverrides,
  writeFloorlessWorkspace,
} from '../src/override-floors.ts';

// A lockfile carrying only the sections the review reads.
const lockfile = (packages: string[], importers: string[] = ['.']): string =>
  [
    "lockfileVersion: '9.0'",
    '',
    'importers:',
    '',
    ...importers.flatMap((importer) => [`  ${importer}:`, '    devDependencies: {}', '']),
    'packages:',
    '',
    ...packages.flatMap((key) => [`  ${key}:`, '    resolution: {integrity: sha512-x}', '']),
    'snapshots:',
    '',
    ...packages.flatMap((key) => [`  ${key}: {}`, '']),
  ].join('\n');

const versionsOf = (packages: string[]) => lockfileVersions(lockfile(packages));

const review = (overrides: Record<string, string>, current: string[], floorless: string[]) =>
  reviewOverrideFloors(
    parseOverrideFloors(overrides).floors,
    versionsOf(current),
    versionsOf(floorless),
  );

describe('parseVersion and compareVersions', () => {
  it('orders releases numerically and a prerelease before its release', () => {
    const order = ['1.2.2', '1.2.10', '1.10.0', '2.0.0-beta.1', '2.0.0']
      .map((text) => parseVersion(text))
      .filter((version) => version !== undefined);
    expect(order).toHaveLength(5);
    order.slice(1).forEach((version, i) => {
      const previous = order[i];
      expect(previous && compareVersions(previous, version)).toBeLessThan(0);
    });
  });

  it('orders prerelease identifiers by semver precedence', () => {
    const order = [
      '2.0.0-alpha',
      '2.0.0-alpha.1',
      '2.0.0-alpha.beta',
      '2.0.0-beta',
      '2.0.0-beta.2',
      '2.0.0-beta.10',
      '2.0.0-rc.1',
      '2.0.0',
    ]
      .map((text) => parseVersion(text))
      .filter((version) => version !== undefined);
    expect(order).toHaveLength(8);
    order.slice(1).forEach((version, i) => {
      const previous = order[i];
      expect(previous && compareVersions(previous, version)).toBeLessThan(0);
      expect(previous && compareVersions(version, previous)).toBeGreaterThan(0);
    });
  });

  it('refuses text that is not a version', () => {
    expect(parseVersion('link:packages/x')).toBeUndefined();
    expect(parseVersion('https://example.com/x.tgz')).toBeUndefined();
  });
});

describe('lockfileVersions and lockfileImporters', () => {
  it('reads every version under packages:, scoped and quoted names included', () => {
    const versions = versionsOf([
      'esbuild@0.18.20',
      'esbuild@0.28.2',
      "'@esbuild/darwin-arm64@0.28.2'",
      'vite@8.0.16(@types/node@25.9.9)',
    ]);
    expect(versions.get('esbuild')?.map((v) => v.minor)).toEqual([18, 28]);
    expect(versions.get('@esbuild/darwin-arm64')).toHaveLength(1);
    expect(versions.get('vite')?.[0]?.major).toBe(8);
  });

  it('does not read keys from snapshots: or importers:', () => {
    const text = lockfile(['a@1.0.0'], ['.', 'packages/b@2.0.0']);
    expect([...lockfileVersions(text).keys()]).toEqual(['a']);
    expect(lockfileImporters(text)).toEqual(['.', 'packages/b@2.0.0']);
  });
});

describe('parseOverrideFloors', () => {
  it('recognises the three selector forms and the three floor operators', () => {
    const { floors, unchecked } = parseOverrideFloors({
      postcss: '^8.5.18',
      'brace-expansion@5': '~5.0.12',
      'source-map-js@<1.2.2': '>=1.2.2',
      '@scope/pkg': '^2.0.0',
      '@scope/other@3': '^3.1.0',
    });
    expect(unchecked).toEqual([]);
    expect(floors.map((floor) => [floor.name, floor.matches.kind])).toEqual([
      ['postcss', 'any'],
      ['brace-expansion', 'major'],
      ['source-map-js', 'below'],
      ['@scope/pkg', 'any'],
      ['@scope/other', 'major'],
    ]);
  });

  it('skips overrides that are not floors', () => {
    const { floors, unchecked } = parseOverrideFloors({
      exact: '1.2.3',
      alias: 'npm:other@^1.0.0',
      removed: '-',
      linked: 'link:../x',
      reference: '$exact',
    });
    expect(floors).toEqual([]);
    expect(unchecked).toEqual([]);
  });

  it('reports a floor whose selector it cannot judge', () => {
    const { floors, unchecked } = parseOverrideFloors({
      'parent>child': '^1.0.0',
      'pkg@^2': '^2.5.0',
    });
    expect(floors).toEqual([]);
    expect(unchecked.map((entry) => entry.selector)).toEqual(['parent>child', 'pkg@^2']);
  });

  it('reports a value that starts like a floor but is not a single bound', () => {
    const { floors, unchecked } = parseOverrideFloors({
      ranged: '>=1.2.3 <2.0.0',
      either: '^1.0.0 || ^2.0.0',
    });
    expect(floors).toEqual([]);
    expect(unchecked).toEqual([
      { selector: 'ranged', floor: '>=1.2.3 <2.0.0', why: 'the value is not a single lower bound' },
      {
        selector: 'either',
        floor: '^1.0.0 || ^2.0.0',
        why: 'the value is not a single lower bound',
      },
    ]);
  });
});

describe('reviewOverrideFloors', () => {
  it('keeps a bare-name floor that something would resolve below', () => {
    const result = review(
      { postcss: '^8.5.18' },
      ['postcss@8.5.30'],
      ['postcss@8.4.31', 'postcss@8.5.30'],
    );
    expect(result).toEqual({ stale: [], unchecked: [] });
  });

  it('counts a lower major as below a bare-name floor', () => {
    const result = review({ 'js-yaml': '^4.3.2' }, ['js-yaml@4.3.2'], ['js-yaml@3.14.1']);
    expect(result.stale).toEqual([]);
  });

  it('flags a bare-name floor nothing resolves below', () => {
    const result = review(
      { 'js-yaml': '^4.3.2' },
      ['js-yaml@4.3.2'],
      ['js-yaml@4.3.2', 'js-yaml@5.5.0'],
    );
    expect(result.stale).toEqual([
      {
        selector: 'js-yaml',
        floor: '^4.3.2',
        why: 'without the override nothing resolves below 4.3.2',
      },
    ]);
  });

  it('flags a floor whose package left the tree, without needing the re-resolution', () => {
    const result = reviewOverrideFloors(
      parseOverrideFloors({ sharp: '^0.35.0' }).floors,
      versionsOf(['postcss@8.5.30']),
      'resolution failed',
    );
    expect(result).toEqual({
      stale: [{ selector: 'sharp', floor: '^0.35.0', why: 'no sharp left in pnpm-lock.yaml' }],
      unchecked: [],
    });
  });

  it('judges a name@major floor against that major only', () => {
    const overrides = { 'brace-expansion@1': '^1.1.21' };
    // A lower copy of another major does not keep it.
    expect(
      review(
        overrides,
        ['brace-expansion@1.1.21'],
        ['brace-expansion@1.1.21', 'brace-expansion@0.9.0'],
      ).stale,
    ).toHaveLength(1);
    // A lower copy of the same major does.
    expect(review(overrides, ['brace-expansion@1.1.21'], ['brace-expansion@1.1.11']).stale).toEqual(
      [],
    );
  });

  it('flags a name@major floor whose major left the tree', () => {
    const result = review(
      { 'brace-expansion@1': '^1.1.21' },
      ['brace-expansion@5.0.12'],
      ['brace-expansion@5.0.12'],
    );
    expect(result.stale).toEqual([
      {
        selector: 'brace-expansion@1',
        floor: '^1.1.21',
        why: 'no brace-expansion@1 left in pnpm-lock.yaml',
      },
    ]);
  });

  it('judges a name@<version floor by the package name, since the override rewrites the range', () => {
    const overrides = { 'source-map-js@<1.2.2': '^1.2.2' };
    expect(review(overrides, ['source-map-js@1.2.2'], ['source-map-js@1.0.2']).stale).toEqual([]);
    expect(review(overrides, ['source-map-js@1.2.2'], ['source-map-js@1.2.2']).stale).toEqual([
      {
        selector: 'source-map-js@<1.2.2',
        floor: '^1.2.2',
        why: 'without the override nothing resolves below 1.2.2',
      },
    ]);
    expect(review(overrides, ['postcss@8.5.30'], []).stale[0]?.why).toBe(
      'no source-map-js left in pnpm-lock.yaml',
    );
  });

  it('marks a floor still in the tree as unchecked when the re-resolution failed', () => {
    const result = reviewOverrideFloors(
      parseOverrideFloors({ postcss: '^8.5.18' }).floors,
      versionsOf(['postcss@8.5.30']),
      'resolution failed',
    );
    expect(result).toEqual({
      stale: [],
      unchecked: [{ selector: 'postcss', floor: '^8.5.18', why: 'resolution failed' }],
    });
  });

  it('marks every floor unchecked, not stale, when no versions could be read from the lockfile', () => {
    const unread = "lockfileVersion: '9.0'\n\nsnapshots:\n\n  postcss@8.5.30: {}\n";
    const result = reviewOverrideFloors(
      parseOverrideFloors({ postcss: '^8.5.18', 'js-yaml': '^4.3.2' }).floors,
      lockfileVersions(unread),
      versionsOf(['postcss@8.5.30']),
    );
    const why = 'no versions could be read from pnpm-lock.yaml';
    expect(result).toEqual({
      stale: [],
      unchecked: [
        { selector: 'postcss', floor: '^8.5.18', why },
        { selector: 'js-yaml', floor: '^4.3.2', why },
      ],
    });
  });

  it('keeps a prerelease floor that a lower prerelease would resolve below', () => {
    expect(
      review({ pkg: '^2.0.0-beta.10' }, ['pkg@2.0.0-beta.10'], ['pkg@2.0.0-beta.2']).stale,
    ).toEqual([]);
  });
});

describe('writeFloorlessWorkspace and reviewRootOverrides (real files)', () => {
  const dirs: string[] = [];
  const tempDir = (): string => {
    const dir = mkdtempSync(join(tmpdir(), 'override-floors-test-'));
    dirs.push(dir);
    return dir;
  };
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  const writeRepo = (overrides: Record<string, string>, packages: string[]): string => {
    const root = tempDir();
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ name: 'root', pnpm: { overrides, packageExtensions: {} } }),
    );
    writeFileSync(join(root, 'pnpm-lock.yaml'), lockfile(packages, ['.', 'packages/a']));
    writeFileSync(join(root, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n");
    mkdirSync(join(root, 'packages', 'a'), { recursive: true });
    writeFileSync(join(root, 'packages', 'a', 'package.json'), '{"name":"a"}');
    return root;
  };

  it('copies the manifests and removes only the named floors', () => {
    const root = writeRepo({ postcss: '^8.5.18', exact: '1.0.0' }, ['postcss@8.5.30']);
    const dest = tempDir();
    writeFloorlessWorkspace(root, dest, ['postcss']);

    const manifest = JSON.parse(readFileSync(join(dest, 'package.json'), 'utf8')) as {
      pnpm: Record<string, unknown>;
    };
    expect(manifest.pnpm).toEqual({ overrides: { exact: '1.0.0' }, packageExtensions: {} });
    expect(readFileSync(join(dest, 'packages', 'a', 'package.json'), 'utf8')).toBe('{"name":"a"}');
    expect(readFileSync(join(dest, 'pnpm-workspace.yaml'), 'utf8')).toContain('packages/*');
    expect(readFileSync(join(dest, 'pnpm-lock.yaml'), 'utf8')).toContain('postcss@8.5.30');
  });

  it('copies the importers when the root path ends in a separator', () => {
    const root = writeRepo({ postcss: '^8.5.18' }, ['postcss@8.5.30']);
    const dest = tempDir();
    writeFloorlessWorkspace(`${root}${sep}`, `${dest}${sep}`, ['postcss']);
    expect(readFileSync(join(dest, 'packages', 'a', 'package.json'), 'utf8')).toBe('{"name":"a"}');
  });

  it('does not copy an importer outside the root', () => {
    const base = tempDir();
    const root = join(base, 'repo');
    mkdirSync(join(base, 'outside'), { recursive: true });
    mkdirSync(root);
    writeFileSync(join(base, 'outside', 'package.json'), '{}');
    writeFileSync(join(root, 'package.json'), '{}');
    writeFileSync(join(root, 'pnpm-lock.yaml'), lockfile([], ['.', '../outside']));
    const dest = join(tempDir(), 'nested', 'dest');
    mkdirSync(dest, { recursive: true });

    writeFloorlessWorkspace(root, dest, []);
    expect(readFileSync(join(dest, 'package.json'), 'utf8')).toBe('{}\n');
    expect(() => readFileSync(join(dest, '..', 'outside', 'package.json'))).toThrow();
  });

  it('drops an overrides map left empty', () => {
    const root = writeRepo({ postcss: '^8.5.18' }, ['postcss@8.5.30']);
    const dest = tempDir();
    writeFloorlessWorkspace(root, dest, ['postcss']);
    const manifest = JSON.parse(readFileSync(join(dest, 'package.json'), 'utf8')) as {
      pnpm: Record<string, unknown>;
    };
    expect(manifest.pnpm).toEqual({ packageExtensions: {} });
  });

  it('judges each floor against the lockfile the resolver leaves behind', () => {
    const root = writeRepo({ postcss: '^8.5.18', 'js-yaml': '^4.3.2', sharp: '^0.35.0' }, [
      'postcss@8.5.30',
      'js-yaml@4.3.2',
    ]);
    let handed: string | undefined;
    const result = reviewRootOverrides(root, (dir) => {
      handed = dir;
      const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
        pnpm: { overrides?: unknown };
      };
      expect(manifest.pnpm.overrides).toBeUndefined();
      writeFileSync(
        join(dir, 'pnpm-lock.yaml'),
        lockfile(['postcss@8.4.31', 'postcss@8.5.30', 'js-yaml@4.3.2']),
      );
    });

    expect(result.stale.map((entry) => entry.selector)).toEqual(['js-yaml', 'sharp']);
    expect(result.unchecked).toEqual([]);
    expect(handed).toBeDefined();
    // The scratch copy is removed whatever the outcome.
    expect(() => readFileSync(join(handed ?? '', 'package.json'))).toThrow();
  });

  it('reports a resolver failure as unchecked rather than stale', () => {
    const root = writeRepo({ postcss: '^8.5.18' }, ['postcss@8.5.30']);
    const result = reviewRootOverrides(root, () => {
      throw new Error(' WARN  deprecated\n\n ERR_PNPM_FETCH_404  not found\n');
    });
    expect(result.stale).toEqual([]);
    expect(result.unchecked).toEqual([
      {
        selector: 'postcss',
        floor: '^8.5.18',
        why: 'the workspace could not be resolved without the floors',
      },
    ]);
    expect(result.error).toBe(
      'pnpm could not resolve the workspace without the floors: ERR_PNPM_FETCH_404 not found',
    );
  });

  it('never throws when the repository cannot be read', () => {
    const result = reviewRootOverrides(join(tempDir(), 'missing'), () => {
      throw new Error('resolver must not run');
    });
    expect(result.stale).toEqual([]);
    expect(result.error).toContain('could not read the overrides');
  });

  it('does not run the resolver when there are no floors', () => {
    const root = writeRepo({ exact: '1.0.0' }, ['exact@1.0.0']);
    const result = reviewRootOverrides(root, () => {
      throw new Error('resolver must not run');
    });
    expect(result).toEqual({ stale: [], unchecked: [] });
  });
});

describe('buildReport override sections', () => {
  const base = {
    mode: 'workspace' as const,
    counts: {},
    blocking: [],
    waived: [],
    nonBlocking: [],
    stale: [],
  };

  it('lists stale floors as their own informational section', () => {
    const overrides: OverrideReview = {
      stale: [{ selector: 'js-yaml', floor: '^4.3.2', why: 'nothing resolves below 4.3.2' }],
      unchecked: [{ selector: 'a>b', floor: '^1.0.0', why: 'not reviewed' }],
    };
    const report = buildReport({ ...base, overrides });
    expect(report).toContain('No blocking advisories.');
    expect(report).toContain(
      '## Stale override floors (1) — remove these\n\n- js-yaml: ^4.3.2 — nothing resolves below 4.3.2',
    );
    expect(report).toContain('## Override floors not checked (1)\n\n- a>b: ^1.0.0 — not reviewed');
  });

  it('reports a review that could not start', () => {
    const report = buildReport({
      ...base,
      overrides: { stale: [], unchecked: [], error: 'could not read the overrides: ENOENT' },
    });
    expect(report).toContain('## Override floors not checked\n\ncould not read the overrides');
  });

  it('adds nothing when every floor holds, or when no review ran', () => {
    const withReview = buildReport({ ...base, overrides: { stale: [], unchecked: [] } });
    expect(withReview).toBe(buildReport(base));
    expect(withReview).not.toContain('override');
  });
});
