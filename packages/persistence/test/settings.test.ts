import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyOnboarding, readWorkspaceSettings } from '../src/settings.ts';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-settings-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function writeSettings(contents: unknown): void {
  const dir = join(base, 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'settings.json'), JSON.stringify(contents));
}

describe('readWorkspaceSettings', () => {
  it('returns unonboarded defaults when settings.json is absent', () => {
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.policy).toBe('redact');
    expect(settings.onboardedAt).toBeUndefined();
  });

  it('reads saved answers', () => {
    writeSettings({
      specVersion: 1,
      runMode: 'standalone',
      policy: 'warn',
      onboardedAt: '2026-06-19T00:00:00.000Z',
    });
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.policy).toBe('warn');
    expect(settings.onboardedAt).toBe('2026-06-19T00:00:00.000Z');
  });

  it("reads a settings.json carrying the retired 'attached' runMode as standalone", () => {
    writeSettings({ specVersion: 1, runMode: 'attached', policy: 'warn' });
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.policy).toBe('warn'); // the rest of the file is untouched
  });

  it('default-fills missing keys so an older partial settings.json still parses', () => {
    writeSettings({ policy: 'warn' });
    const settings = readWorkspaceSettings(base);
    expect(settings.policy).toBe('warn');
    expect(settings.runMode).toBe('standalone'); // defaulted
    expect(settings.historicalAccess).toBe('session-only'); // defaulted, never an assumed grant
    expect(settings.onboardedAt).toBeUndefined();
  });

  it('falls back to defaults on a corrupt settings.json (fail-open)', () => {
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'settings.json'), '{ not json');
    const settings = readWorkspaceSettings(base);
    expect(settings.runMode).toBe('standalone');
    expect(settings.onboardedAt).toBeUndefined();
  });

  it('is a pure reader — reading does not alter settings.json mode', () => {
    if (process.platform === 'win32') return;
    // The self-heal deliberately lives in the write/init/loadConfig paths, not
    // here: a documented fail-open reader (also called from a web-ui page render)
    // must not chmod on every read. This pins that contract so nobody re-adds it.
    writeSettings({ specVersion: 1, runMode: 'standalone', policy: 'warn' });
    const file = join(base, 'settings', 'settings.json');
    chmodSync(file, 0o644);

    const settings = readWorkspaceSettings(base);

    expect(settings.policy).toBe('warn'); // reads correctly
    expect(statSync(file).mode & 0o777).toBe(0o644); // and leaves the mode untouched
  });
});

describe('applyOnboarding', () => {
  it('persists answers, stamps onboardedAt, and writes the file owner-only', () => {
    const saved = applyOnboarding({ policy: 'warn' }, base);
    expect(saved.policy).toBe('warn');
    expect(saved.onboardedAt).toBeDefined();

    const settings = readWorkspaceSettings(base);
    expect(settings.policy).toBe('warn');
    expect(settings.onboardedAt).toBe(saved.onboardedAt);
    if (process.platform !== 'win32') {
      const file = join(base, 'settings', 'settings.json');
      expect(statSync(file).mode & 0o777).toBe(0o600);
    }
  });

  it('writes settings.json 0600 even over a leftover loose .tmp', () => {
    if (process.platform === 'win32') return;
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    // A crash between the tmp write and the rename can leave a settings.json.tmp
    // behind. writeFileSync's `mode` option is honored only on creation, so the
    // owner-only writer clears a stale tmp first (and re-tightens after the
    // rename) rather than carrying its loose mode onto settings.json.
    const tmp = join(dir, 'settings.json.tmp');
    writeFileSync(tmp, 'stale');
    chmodSync(tmp, 0o666);

    applyOnboarding({ policy: 'warn' }, base);

    const file = join(dir, 'settings.json');
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('round-trips the Data Shares kill-switch through the settings file', () => {
    // Defaults on, so disabling it must survive the write/read cycle rather than
    // being re-defaulted back to true on the next read.
    expect(readWorkspaceSettings(base).dataSharesInPlace).toBe(true);

    const saved = applyOnboarding({ dataSharesInPlace: false }, base);
    expect(saved.dataSharesInPlace).toBe(false);
    expect(readWorkspaceSettings(base).dataSharesInPlace).toBe(false);

    expect(applyOnboarding({ dataSharesInPlace: true }, base).dataSharesInPlace).toBe(true);
    expect(readWorkspaceSettings(base).dataSharesInPlace).toBe(true);
  });

  it('merges additive answers across calls and keeps the original onboardedAt', () => {
    const first = applyOnboarding({ policy: 'warn' }, base);
    const second = applyOnboarding({ historicalAccess: 'full' }, base);
    expect(second.policy).toBe('warn'); // preserved from the first call
    expect(second.historicalAccess).toBe('full'); // newly applied
    expect(second.onboardedAt).toBe(first.onboardedAt); // stable across edits
  });
});
