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
});
