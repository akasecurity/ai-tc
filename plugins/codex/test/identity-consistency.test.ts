import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  crossPackageSpecifiers,
  declaredTestInputs,
  turboRootInput,
} from '../../../test/helpers/turbo-inputs.ts';

// The two manifests that name this plugin to the outside world: npm's
// package.json and the Codex plugin manifest. The release workflow publishes
// from package.json while the Codex host reads .codex-plugin/plugin.json, so a
// version drift ships an artifact that reports two different versions.

interface Manifest {
  name?: string;
  version?: string;
}

function readManifest(rel: string): Manifest {
  return JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8')) as Manifest;
}

describe('plugin identity consistency', () => {
  it('plugin.json version equals package.json version (lockstep)', () => {
    const plugin = readManifest('../.codex-plugin/plugin.json');
    const pkg = readManifest('../package.json');
    expect(plugin.version).toBe(pkg.version);
  });

  it('cli, claude-code plugin, and codex plugin share one version line', () => {
    // All three artifacts bundle the same @akasecurity/* workspace packages and
    // release together, so a lone bump ships artifacts that disagree about
    // which workspace state they carry.
    const cli = readManifest('../../../cli/package.json');
    const claudeCode = readManifest('../../../plugins/claude-code/package.json');
    const codex = readManifest('../package.json');
    expect(claudeCode.version).toBe(cli.version);
    expect(codex.version).toBe(cli.version);
  });
});

describe('turbo hashes every cross-package file this suite reads', () => {
  // The version-line case above reads two manifests that belong to other
  // packages, and neither package is a dependency of this one. Unnamed, a
  // CLI-only version bump leaves this task's hash untouched and turbo replays a
  // cached pass at the one moment that case exists to fail.
  //
  // The files are derived from this file's own relative literals rather than
  // listed, so a read added above is demanded here without anyone remembering
  // — PROVIDED it is spelled as one relative literal. A read assembled from an
  // anchor plus a segment (`'../../..' + '/cli/…'`, `join(repoRoot, 'cli', …)`)
  // is invisible to the scan, and the pin below moves only for what the scan
  // sees, so that shape stays green unnamed. Spell the read as one literal.
  const packageDir = fileURLToPath(new URL('..', import.meta.url));
  const reads = crossPackageSpecifiers({
    testFile: fileURLToPath(import.meta.url),
    packageDir,
    repoRoot: fileURLToPath(new URL('../../..', import.meta.url)),
  });

  it('finds the reads it is meant to cover', () => {
    // Without this a scan that matched nothing would demand nothing, and the
    // membership check below would pass over an empty list.
    expect(reads).toEqual(['cli/package.json', 'plugins/claude-code/package.json']);
  });

  it('names each of them in plugins/codex/turbo.json', () => {
    const inputs = declaredTestInputs(packageDir);
    expect(
      reads.filter((file) => !inputs.includes(turboRootInput(file))),
      'read by this suite and not hashed by its test task, so an edit there replays a cached pass',
    ).toEqual([]);
  });

  it("keeps the package's own files in the hash", () => {
    // Naming inputs REPLACES the default set, so dropping this entry would leave
    // the task hashing the cross-package files and nothing of this package.
    expect(declaredTestInputs(packageDir)).toContain('$TURBO_DEFAULT$');
  });
});
