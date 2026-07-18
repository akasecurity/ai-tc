import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir, loadConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { parseHomeFlag } from '../src/home-flag.ts';

// The wizard entry scripts accept a `--home <path>` override so
// the journey harness can point the whole chain at a throwaway ~/.aka home. The
// override is a flag (never an env var — the plugin's n/no-process-env rule
// forbids reading process.env for it).
describe('parseHomeFlag — the wizard home override', () => {
  it('extracts `--home <path>`', () => {
    expect(parseHomeFlag(['--home', '/tmp/aka-home'])).toBe('/tmp/aka-home');
  });

  it('extracts `--home=<path>`', () => {
    expect(parseHomeFlag(['--home=/tmp/aka-home'])).toBe('/tmp/aka-home');
  });

  it('finds --home among other flags', () => {
    expect(parseHomeFlag(['--policy', 'warn', '--home', '/tmp/x', '--floor'])).toBe('/tmp/x');
  });

  it('returns undefined when the flag is absent', () => {
    expect(parseHomeFlag(['--triage'])).toBeUndefined();
    expect(parseHomeFlag([])).toBeUndefined();
  });

  it('returns undefined when --home has no value (next token is another flag)', () => {
    expect(parseHomeFlag(['--home', '--triage'])).toBeUndefined();
  });
});

describe('parseHomeFlag threaded into loadConfig', () => {
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-home-flag-'));
  });

  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
  });

  it('threads the override into loadConfig as the store base', () => {
    const cfg = loadConfig(parseHomeFlag(['--home', base]));
    expect(cfg.dataDir).toBe(dataDir(base));
  });

  it('omitting --home preserves the default home', () => {
    // parseHomeFlag returns undefined, so loadConfig(undefined) falls back to
    // defaultDataDir() — the store base sits under the OS home, not `base`.
    expect(loadConfig(parseHomeFlag([])).dataDir).not.toBe(dataDir(base));
  });
});
