import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
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

  it('merges additive answers across calls and keeps the original onboardedAt', () => {
    const first = applyOnboarding({ policy: 'warn' }, base);
    const second = applyOnboarding({ historicalAccess: 'full' }, base);
    expect(second.policy).toBe('warn'); // preserved from the first call
    expect(second.historicalAccess).toBe('full'); // newly applied
    expect(second.onboardedAt).toBe(first.onboardedAt); // stable across edits
  });
});
