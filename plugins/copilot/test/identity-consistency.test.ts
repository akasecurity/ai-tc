import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  crossPackageSpecifiers,
  declaredTestInputs,
  turboRootInput,
} from '../../../test/helpers/turbo-inputs.ts';

// The two manifests that name this plugin to the outside world: the npm
// package.json and the plugin manifest at the plugin root. A version drift
// ships an artifact that reports two different versions.

interface Manifest {
  name?: string;
  version?: string;
}

function readManifest(rel: string): Manifest {
  return JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8')) as Manifest;
}

describe('plugin identity consistency', () => {
  it('plugin.json version equals package.json version (lockstep)', () => {
    const plugin = readManifest('../plugin.json');
    const pkg = readManifest('../package.json');
    expect(plugin.version).toBe(pkg.version);
  });

  it('cli and copilot plugin share one version line', () => {
    // Both artifacts bundle the same @akasecurity/* workspace packages, so a
    // lone bump ships artifacts that disagree about which workspace state
    // they carry.
    const cli = readManifest('../../../cli/package.json');
    const copilot = readManifest('../package.json');
    expect(copilot.version).toBe(cli.version);
  });
});

describe('turbo hashes every cross-package file this suite reads', () => {
  // The version-line case above reads a manifest that belongs to another
  // package this one does not depend on. Unnamed, a CLI-only version bump
  // leaves this task's hash untouched and turbo replays a cached pass at the
  // one moment that case exists to fail. The files are derived from this
  // file's own relative literals; spell each read as one relative literal.
  const packageDir = fileURLToPath(new URL('..', import.meta.url));
  const reads = crossPackageSpecifiers({
    testFile: fileURLToPath(import.meta.url),
    packageDir,
    repoRoot: fileURLToPath(new URL('../../..', import.meta.url)),
  });

  it('finds the reads it is meant to cover', () => {
    expect(reads).toEqual(['cli/package.json']);
  });

  it('names each of them in plugins/copilot/turbo.json', () => {
    const inputs = declaredTestInputs(packageDir);
    expect(
      reads.filter((file) => !inputs.includes(turboRootInput(file))),
      'read by this suite and not hashed by its test task, so an edit there replays a cached pass',
    ).toEqual([]);
  });

  it("keeps the package's own files in the hash", () => {
    expect(declaredTestInputs(packageDir)).toContain('$TURBO_DEFAULT$');
  });
});
