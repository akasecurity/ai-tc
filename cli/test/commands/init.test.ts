import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { dbPath, settingsDir } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runInit } from '../../src/commands/init.ts';

// Force the offer's non-interactive branch to emit: report no installed plugin so
// offerPluginInstall reaches the print path, independent of the host's ~/.claude.
vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return { ...actual, installedPluginVersions: vi.fn(() => new Map<string, string>()) };
});

let dir: string;
let stdinTTY: PropertyDescriptor | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-init-'));
  // The interactive offer is TTY-gated; force the non-TTY branch so runInit
  // prints the offer copy without blocking on a confirm prompt.
  stdinTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  if (stdinTTY) Object.defineProperty(process.stdin, 'isTTY', stdinTTY);
  else delete (process.stdin as { isTTY?: boolean }).isTTY;
  vi.restoreAllMocks();
});

describe('plugin-install offer identity', () => {
  it('emits offer copy carrying the canonical product name and tagline', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('AKA Security');
    expect(out).toContain('We secure agent harnesses at the source.');
  });
});

describe('runInit contract', () => {
  it('still scaffolds ~/.aka and asks no posture questions', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);

    // Scaffolding: the settings file and the SQLite store both land under the home.
    expect(existsSync(join(settingsDir(dir), 'settings.json'))).toBe(true);
    expect(existsSync(dbPath(dir))).toBe(true);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain(`Initialized AKA at ${dir}`);
    // init never interrogates the user about detection posture or historical access.
    expect(out).not.toMatch(/posture/i);
    expect(out).not.toMatch(/historical access/i);
  });
});
