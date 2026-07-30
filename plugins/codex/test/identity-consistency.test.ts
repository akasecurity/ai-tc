import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

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
