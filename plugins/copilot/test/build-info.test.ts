import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  harnessVersionFromArgv,
  MANIFEST_ARGV_INDEX,
  PLUGIN_PACKAGE,
  pluginBuild,
} from '../src/build-info.ts';

// The identity every attached posture report from this plugin carries. Both
// halves are pinned against the files that actually define them, so a rename of
// the npm package or a manifest layout change fails here rather than shipping
// reports under a stale identity.
describe('pluginBuild', () => {
  it('names the npm package this plugin publishes as', async () => {
    const { readFileSync } = await import('node:fs');
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      name: string;
    };
    expect(PLUGIN_PACKAGE).toBe(pkg.name);
  });

  it('reads the version from the manifest beside the running code', async () => {
    const { readFileSync } = await import('node:fs');
    const manifest = JSON.parse(
      readFileSync(new URL('../plugin.json', import.meta.url), 'utf8'),
    ) as { version: string };
    expect(manifest.version).toBeTypeOf('string');
    expect(pluginBuild()).toEqual({ package: PLUGIN_PACKAGE, version: manifest.version });
  });
});

describe('harnessVersionFromArgv', () => {
  const dirs: string[] = [];

  function manifestAt(version: unknown): string {
    const dir = mkdtempSync(join(tmpdir(), 'aka-copilot-manifest-'));
    dirs.push(dir);
    const file = join(dir, 'plugin.json');
    writeFileSync(file, JSON.stringify({ version }));
    return file;
  }

  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  // The offset itself, stated as a number and driven as behaviour. The sibling
  // plugins read the manifest at argv[2]; here argv[2] is the event token, so a
  // copied hook that kept the sibling's index would parse the event name as a
  // path and report no version at all.
  it('reads the manifest one place right of the sibling plugins', () => {
    expect(MANIFEST_ARGV_INDEX).toBe(3);
  });

  it('reads the version from the manifest at argv[3]', () => {
    const file = manifestAt('9.9.9');
    expect(harnessVersionFromArgv(['node', 'script.js', 'preToolUse', file])).toBe('9.9.9');
  });

  // The regression the offset exists to prevent, pinned directly: with the
  // sibling's index the manifest sits at argv[3] and argv[2] is an event name,
  // so reading argv[2] answers undefined rather than the version.
  it('does not read the event token as a manifest path', () => {
    const file = manifestAt('9.9.9');
    const argv = ['node', 'script.js', 'preToolUse', file];
    expect(argv[2]).toBe('preToolUse');
    expect(harnessVersionFromArgv(argv.slice(0, 3))).toBeUndefined();
  });

  it('answers undefined when no manifest path is passed', () => {
    expect(harnessVersionFromArgv(['node', 'script.js', 'preToolUse'])).toBeUndefined();
  });

  it('answers undefined for an unreadable manifest', () => {
    expect(
      harnessVersionFromArgv([
        'node',
        'script.js',
        'preToolUse',
        join(tmpdir(), 'aka-absent.json'),
      ]),
    ).toBeUndefined();
  });

  it('answers undefined for a manifest carrying no string version', () => {
    expect(
      harnessVersionFromArgv(['node', 'script.js', 'preToolUse', manifestAt(3)]),
    ).toBeUndefined();
  });
});
