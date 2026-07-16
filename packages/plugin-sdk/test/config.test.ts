import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyOnboarding, loadConfig } from '../src/config.ts';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-config-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function writeSettings(contents: unknown): void {
  const dir = join(base, 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'settings.json'), JSON.stringify(contents));
}

describe('loadConfig', () => {
  it('returns unonboarded defaults when settings.json is absent', () => {
    const cfg = loadConfig(base);
    expect(cfg.onboarded).toBe(false);
    expect(cfg.settings.runMode).toBe('standalone');
    expect(cfg.settings.policy).toBe('redact');
  });

  it('resolves the on-disk layout under the base', () => {
    const cfg = loadConfig(base);
    expect(cfg.settingsDir).toBe(join(base, 'settings'));
    expect(cfg.dataDir).toBe(join(base, 'data'));
    expect(cfg.dbPath).toBe(join(base, 'data', 'aka.db'));
  });

  it('resolves the provider from env (Anthropic-direct by default in the test env)', () => {
    // The env-derived provider rides on the config so SessionStart can snapshot it
    // onto the session root. With no Bedrock/Vertex/gateway env set, it is
    // Anthropic-direct. Resolution itself is covered in ./provider.test.ts; here we
    // only assert loadConfig surfaces a valid ResolvedProvider.
    const cfg = loadConfig(base);
    expect(cfg.provider).toBeDefined();
    expect(['anthropic', 'bedrock', 'vertex', 'gateway']).toContain(cfg.provider.provider);
  });

  it('is onboarded once onboardedAt is recorded, and reads saved answers', () => {
    writeSettings({
      specVersion: 1,
      runMode: 'standalone',
      policy: 'warn',
      onboardedAt: '2026-06-19T00:00:00.000Z',
    });
    const cfg = loadConfig(base);
    expect(cfg.onboarded).toBe(true);
    expect(cfg.settings.runMode).toBe('standalone');
    expect(cfg.settings.policy).toBe('warn');
  });

  it('default-fills missing keys so an older partial settings.json still parses', () => {
    writeSettings({ policy: 'warn' });
    const cfg = loadConfig(base);
    expect(cfg.settings.policy).toBe('warn');
    expect(cfg.settings.runMode).toBe('standalone'); // defaulted
    expect(cfg.settings.historicalAccess).toBe('session-only'); // defaulted, never an assumed grant
    expect(cfg.onboarded).toBe(false); // no onboardedAt
  });

  it('falls back to defaults on a corrupt settings.json (fail-open)', () => {
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'settings.json'), '{ not json');
    const cfg = loadConfig(base);
    expect(cfg.onboarded).toBe(false);
    expect(cfg.settings.runMode).toBe('standalone');
  });

  it('migrates a pre-layout flat config.json into settings/ on load', () => {
    // Old installs wrote ~/.aka/config.json directly under the base; loadConfig
    // moves it into settings/ (the file is carried, never parsed).
    writeFileSync(join(base, 'config.json'), JSON.stringify({ token: 't' }));
    loadConfig(base);
    expect(existsSync(join(base, 'settings', 'config.json'))).toBe(true);
    expect(existsSync(join(base, 'config.json'))).toBe(false);
  });
});

describe('applyOnboarding', () => {
  it('persists answers, stamps onboardedAt, and flips onboarded true', () => {
    const saved = applyOnboarding({ policy: 'warn' }, base);
    expect(saved.policy).toBe('warn');
    expect(saved.onboardedAt).toBeDefined();

    const cfg = loadConfig(base);
    expect(cfg.onboarded).toBe(true);
    expect(cfg.settings.policy).toBe('warn');
  });

  it('merges additive answers across calls and keeps the original onboardedAt', () => {
    const first = applyOnboarding({ policy: 'warn' }, base);
    const second = applyOnboarding({ historicalAccess: 'full' }, base);
    expect(second.policy).toBe('warn'); // preserved from the first call
    expect(second.historicalAccess).toBe('full'); // newly applied
    expect(second.onboardedAt).toBe(first.onboardedAt); // stable across edits
  });
});
