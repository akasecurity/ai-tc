// The argv offset is the one thing about this host's build-info that differs
// from all three siblings, and getting it wrong is SILENT. `argv[2]` here is
// the event name; a reader copied from a sibling would find `'preToolUse'`
// there, `readFileSync` would throw ENOENT, the best-effort catch would swallow
// it, and the plugin version would simply be absent from every inventory row.
// A missing field, never an error — so the offset is pinned directly rather
// than left to be noticed.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { harnessVersionFromArgv, PLUGIN_PACKAGE, pluginBuild } from '../src/build-info.ts';

// `readManifestBuild` memoises per manifest URL, including misses, so every
// case here writes to a path of its own. A shared path would make the second
// case read the first one's answer.
const roots: string[] = [];
function manifestAt(version: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'aka-copilot-build-'));
  roots.push(dir);
  const file = join(dir, 'plugin.json');
  writeFileSync(file, JSON.stringify(version === undefined ? {} : { version }));
  return file;
}

afterAll(() => {
  for (const dir of roots) rmSync(dir, { recursive: true, force: true });
});

/** argv as node builds it: [execPath, scriptPath, <event>, <manifest?>]. */
const argv = (...tail: string[]): string[] => ['/usr/bin/node', '/p/scripts/x.js', ...tail];

describe('harnessVersionFromArgv', () => {
  it('reads the manifest at argv[3]', () => {
    const file = manifestAt('1.2.3');
    expect(harnessVersionFromArgv(argv('sessionStart', file))).toBe('1.2.3');
  });

  it('does NOT read argv[2], which is the event name', () => {
    // The discriminating case. A reader copied from a sibling looks here, finds
    // the event token, and answers undefined for every session — while every
    // other case in this file that merely checked "some version came back"
    // would still pass if the reader looked at BOTH slots.
    const file = manifestAt('1.2.3');
    expect(harnessVersionFromArgv(argv(file))).toBeUndefined();
    expect(harnessVersionFromArgv(argv(file, 'sessionStart'))).toBeUndefined();
  });

  it('returns undefined when no manifest path was passed', () => {
    expect(harnessVersionFromArgv(argv('sessionStart'))).toBeUndefined();
    expect(harnessVersionFromArgv(argv())).toBeUndefined();
    expect(harnessVersionFromArgv([])).toBeUndefined();
    expect(harnessVersionFromArgv(argv('sessionStart', ''))).toBeUndefined();
  });

  it('returns undefined for an unreadable or versionless manifest', () => {
    // Best-effort is the contract: the harness dimension still resolves on
    // `tool` alone, so a bad manifest omits a field rather than failing a hook.
    expect(harnessVersionFromArgv(argv('sessionStart', manifestAt(undefined)))).toBeUndefined();
    expect(harnessVersionFromArgv(argv('sessionStart', manifestAt(7)))).toBeUndefined();
    expect(
      harnessVersionFromArgv(argv('sessionStart', join(tmpdir(), 'aka-no-such-manifest.json'))),
    ).toBeUndefined();
  });

  it('survives a path carrying a space', () => {
    // `pathToFileURL` rather than a `file://` template. The template produces an
    // invalid URL here, and the failure lands in the best-effort catch as a
    // missing version rather than as anything anyone sees.
    const dir = mkdtempSync(join(tmpdir(), 'aka copilot space-'));
    roots.push(dir);
    const file = join(dir, 'plugin.json');
    writeFileSync(file, JSON.stringify({ version: '9.9.9' }));
    expect(harnessVersionFromArgv(argv('sessionStart', file))).toBe('9.9.9');
  });
});

describe('pluginBuild', () => {
  it('resolves the shipped manifest relative to this module, not the cwd', () => {
    // Hooks and detached children run from arbitrary directories, so a
    // cwd-relative read works on a developer's machine and nowhere else.
    const build = pluginBuild();
    expect(build?.package).toBe(PLUGIN_PACKAGE);
    expect(build?.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('reports the same version the manifest and the package agree on', () => {
    // `test/hooks-manifest.test.ts` holds plugin.json's version equal to
    // package.json's; this holds the READER equal to both, so a reader pointed
    // at the wrong file cannot pass by accident.
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version: string;
    };
    expect(pluginBuild()?.version).toBe(pkg.version);
  });
});
