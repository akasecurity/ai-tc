import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';

import { manifestKindOf } from '@akasecurity/detections';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveNonGitProject, toPosix } from '../src/paths.ts';

// Both scan pipelines derive their NON-git project identity from
// resolveNonGitProject(<scan target dir>, manifestKindOf): the CLI/web-ui
// pipeline (@akasecurity/local-ops) and the plugin scanner (@akasecurity/scanner).
// A "root scan" passes the project directory; a "subtree scan" passes a nested
// directory. This is the one shared derivation both pipelines share, so proving
// it converges here proves the two pipelines stay byte-identical.

let base: string;

beforeEach(() => {
  // realpath the temp base up front: macOS temp dirs live under a symlink
  // (/var -> /private/var) and resolveNonGitProject keys on the realpath, so
  // building the corpus under the canonical path keeps expectations direct.
  base = realpathSync(mkdtempSync(join(tmpdir(), 'aka-paths-')));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function write(rel: string, content = ''): string {
  const full = join(base, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
  return full;
}

describe('resolveNonGitProject — cross-depth convergence', () => {
  it('keys a root scan and a subtree scan of one manifest-bearing project identically', () => {
    write('package.json', JSON.stringify({ name: 'proj', dependencies: { stripe: '^14' } }));
    const payFile = write('src/pay.ts', "fetch('https://api.stripe.com/v1/charges')\n");

    const rootScan = resolveNonGitProject(base, manifestKindOf);
    const subtreeScan = resolveNonGitProject(join(base, 'src'), manifestKindOf);

    // Identical reconcile key: the subtree no longer mints a second project.
    expect(subtreeScan.projectKey).toBe(rootScan.projectKey);
    expect(rootScan.projectKey).toBe(`path:${base}`);
    expect(rootScan.project).toBe(basename(base));

    // Identical relative file path for the same on-disk file, from either anchor.
    const relFromRoot = toPosix(relative(rootScan.root, payFile));
    const relFromSubtree = toPosix(relative(subtreeScan.root, payFile));
    expect(relFromRoot).toBe('src/pay.ts');
    expect(relFromSubtree).toBe(relFromRoot);
  });

  it('climbs to the HIGHEST manifest-bearing ancestor (a sub-package resolves to the monorepo root)', () => {
    write('package.json', '{}');
    write('packages/a/package.json', '{}');

    const subPkg = resolveNonGitProject(join(base, 'packages', 'a'), manifestKindOf);
    const deep = resolveNonGitProject(join(base, 'packages', 'a', 'src'), manifestKindOf);

    expect(subPkg.projectKey).toBe(`path:${base}`);
    expect(deep.projectKey).toBe(`path:${base}`);
  });

  it('recognizes a range of manifests, including a .csproj by suffix', () => {
    for (const marker of ['go.mod', 'pyproject.toml', 'Cargo.toml', 'App.csproj']) {
      rmSync(base, { recursive: true, force: true });
      base = realpathSync(mkdtempSync(join(tmpdir(), 'aka-paths-')));
      write(marker, '');
      write('src/pay.ts');
      expect(resolveNonGitProject(join(base, 'src'), manifestKindOf).projectKey).toBe(
        `path:${base}`,
      );
    }
  });
});

describe('resolveNonGitProject — fallback when no project boundary exists', () => {
  it('falls back to the target itself, so different depths do NOT reconcile', () => {
    write('src/pay.ts');

    const rootScan = resolveNonGitProject(base, manifestKindOf);
    const subtreeScan = resolveNonGitProject(join(base, 'src'), manifestKindOf);

    expect(rootScan.projectKey).toBe(`path:${base}`);
    expect(subtreeScan.projectKey).toBe(`path:${join(base, 'src')}`);
    // Divergent by design: with no boundary, a subtree scan cannot be mapped
    // back to the root — there is nothing to anchor on.
    expect(subtreeScan.projectKey).not.toBe(rootScan.projectKey);
  });

  it('does not treat a lockfile as a project marker', () => {
    write('package-lock.json', '{}');
    write('src/pay.ts');

    // manifestKindOf returns null for a lockfile, so there is no anchor above
    // the subtree and it falls back to itself.
    expect(resolveNonGitProject(join(base, 'src'), manifestKindOf).projectKey).toBe(
      `path:${join(base, 'src')}`,
    );
  });
});
