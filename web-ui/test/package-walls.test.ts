import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// The human reveal path (web dashboard → vault) must reach the vault ONLY
// through @akasecurity/persistence. Neither web-ui nor @akasecurity/dashboard-ui may take a
// runtime dependency on the plugin stack — the plugin SDK's vault glue is
// hook-path machinery, and pulling it into the dashboard would route reveals
// around the persistence wall. web-ui's devDependencies legitimately carry
// @akasecurity/plugin-sdk for test-fixture seeding (a documented dev-only
// exception), which is why only the runtime edges are pinned here.

const FORBIDDEN = [
  '@akasecurity/plugin-sdk',
  '@akasecurity/plugin-runtime',
  '@akasecurity/ai-tc-claude-code',
];

interface PackageManifest {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

function runtimeDeps(relativePath: string): string[] {
  const file = fileURLToPath(new URL(relativePath, import.meta.url));
  const pkg = JSON.parse(readFileSync(file, 'utf8')) as PackageManifest;
  return [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.peerDependencies ?? {})];
}

describe('package walls — the human reveal path', () => {
  it('web-ui has no runtime dependency on the plugin stack', () => {
    const deps = runtimeDeps('../package.json');
    for (const name of FORBIDDEN) {
      expect(deps).not.toContain(name);
    }
    // The wall is about the route, not isolation: persistence IS the vault path.
    expect(deps).toContain('@akasecurity/persistence');
  });

  it('@akasecurity/dashboard-ui has no runtime dependency on the plugin stack', () => {
    const deps = runtimeDeps('../../packages/dashboard-ui/package.json');
    for (const name of FORBIDDEN) {
      expect(deps).not.toContain(name);
    }
  });
});
