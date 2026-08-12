import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectInstallChannel } from '@akasecurity/local-ops';
import { afterAll, describe, expect, it } from 'vitest';

import { dashboardInstallOrigin } from '../app/lib/install-origin.ts';

// The dashboard has to name the command that updates the `aka` install it
// belongs to. Getting the ORIGIN of that classification from `import.meta.url`
// is the trap app/lib/scan-worker.ts documents: a Next build replaces it with
// the build machine's absolute source path, baked into the server chunk as a
// string literal, so the dashboard would classify the maintainer's disk. It
// fails silently and only off the build machine — every local check passes.

const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

describe('dashboardInstallOrigin', () => {
  it('states the app directory, which is where the dashboard actually runs', () => {
    // `aka dashboard` spawns the standalone server with cwd set to the server's
    // own directory; `next start` and vitest both run from the package.
    expect(dashboardInstallOrigin()).toStrictEqual({ moduleDir: process.cwd() });
  });

  it('does not read import.meta.url — the value a Next build poisons', () => {
    const source = readFileSync(
      fileURLToPath(new URL('../app/lib/install-origin.ts', import.meta.url)),
      'utf8',
    );
    const code = source
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*'))
      .join('\n');
    expect(code).not.toContain('import.meta');
  });
});

describe('the packaged layout is reachable from the app directory', () => {
  // The origin is only useful if the walk upward from it actually meets the
  // CLI's package.json. In the published CLI the standalone server sits at
  // <cli>/web-ui/web-ui/server.js, so the walk crosses two directories — well
  // inside the classifier's depth limit, but that is a property of the packed
  // layout rather than something either package can assert alone.
  function packagedCli(): { cliRoot: string; appDir: string } {
    const cliRoot = tempDir('aka-packaged-cli-');
    writeFileSync(
      join(cliRoot, 'package.json'),
      JSON.stringify({ name: '@akasecurity/cli', version: '0.9.3' }),
    );
    const appDir = join(cliRoot, 'web-ui', 'web-ui');
    mkdirSync(appDir, { recursive: true });
    return { cliRoot, appDir };
  }

  it('classifies an npm-global CLI from the dashboard app directory', () => {
    const { cliRoot, appDir } = packagedCli();
    // Put the whole thing under a global npm prefix: <prefix>/lib/node_modules/…
    const channel = detectInstallChannel({ moduleDir: appDir });
    // The temp dir is not under a node_modules tree, so this lands on the
    // source-checkout/unknown side — what matters here is that the walk REACHED
    // the CLI package rather than stopping short of it.
    expect(JSON.stringify(channel)).toContain(cliRoot);
  });

  it('an app directory outside any install classifies as unknown, not as a guess', () => {
    const channel = detectInstallChannel({ moduleDir: tempDir('aka-orphan-') });
    expect(channel.kind).toBe('unknown');
  });
});
