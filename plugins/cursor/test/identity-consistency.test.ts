/**
 * This plugin shares the CLI's version line, and its test task hashes the one
 * file outside the package this suite reads, so a CLI-only version bump
 * re-runs it rather than replaying a cached pass.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  crossPackageSpecifiers,
  declaredTestInputs,
  turboRootInput,
} from '../../../test/helpers/turbo-inputs.ts';
import { PLUGIN_PACKAGE } from '../src/identity.ts';

interface Manifest {
  name?: string;
  version?: string;
}

function readManifest(rel: string): Manifest {
  return JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8')) as Manifest;
}

describe('plugin identity consistency', () => {
  it('names the package it is', () => {
    expect(readManifest('../package.json').name).toBe(PLUGIN_PACKAGE);
  });

  it('cli and cursor plugin share one version line', () => {
    const cli = readManifest('../../../cli/package.json');
    const cursor = readManifest('../package.json');
    expect(cursor.version).toBe(cli.version);
  });
});

describe('turbo hashes every cross-package file this suite reads', () => {
  const packageDir = fileURLToPath(new URL('..', import.meta.url));
  const reads = crossPackageSpecifiers({
    testFile: fileURLToPath(import.meta.url),
    packageDir,
    repoRoot: fileURLToPath(new URL('../../..', import.meta.url)),
  });

  it('finds the reads it is meant to cover', () => {
    expect(reads).toEqual(['cli/package.json']);
  });

  it('names each of them in plugins/cursor/turbo.json', () => {
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
