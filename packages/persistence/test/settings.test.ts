import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SimpleDetectionPolicy } from '@akasecurity/schema';
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

  it('reads a settings.json carrying a superseded runMode, keeping its other fields', () => {
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

  it('is a pure reader — reading does not alter settings.json mode', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
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

  it('writes settings.json 0600 even over a leftover loose .tmp', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    // A crash between the tmp write and the rename can leave a stale tmp behind.
    // writeFileSync's `mode` option is honored only on creation, so the owner-only
    // writer clears that tmp first (and re-tightens after the rename) rather than
    // carrying its loose mode onto settings.json.
    //
    // The tmp name has to carry THIS process's pid, because that is the path the
    // writer builds and therefore the only one it can collide with. A plain
    // `settings.json.tmp` is a file the writer never touches, so the fixture is
    // inert and the case holds on the create mode alone — which is what it did
    // until the writer's tmp became per-process.
    const tmp = join(dir, `settings.json.${String(process.pid)}.tmp`);
    writeFileSync(tmp, 'stale');
    chmodSync(tmp, 0o666);

    applyOnboarding({ policy: 'warn' }, base);

    // The writer consumed the planted tmp — it clears that path, writes it
    // exclusively, and removes it again. A tmp still sitting there is one the
    // writer never touched, i.e. the name above has drifted from the one it
    // builds and the fixture is back to being inert. Assert it before the mode,
    // because a mode of 0600 holds on the create mode alone either way.
    expect(existsSync(tmp)).toBe(false);

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

  it('leaves no lock file behind', () => {
    applyOnboarding({ policy: 'warn' }, base);
    // The write lock is a sibling of settings.json. One left behind costs every
    // later writer its full stale wait before it can proceed.
    expect(readdirSync(join(base, 'settings'))).toEqual(['settings.json']);
  });
});

describe('applyOnboarding (derived answers)', () => {
  it('hands the updater the settings already on disk', () => {
    applyOnboarding({ policy: 'warn' }, base);

    let seen: SimpleDetectionPolicy | undefined;
    applyOnboarding((current) => {
      seen = current.policy;
      return { historicalAccess: 'full' };
    }, base);

    expect(seen).toBe('warn');
    expect(readWorkspaceSettings(base).historicalAccess).toBe('full');
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('merges what the updater returns, exactly as a plain answer object would', () => {
    const saved = applyOnboarding(() => ({ policy: 'warn' }), base);
    expect(saved.policy).toBe('warn');
    expect(saved.onboardedAt).toBeDefined();
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('lets an updater carry a value forward from the current settings', () => {
    // The dashboard's shape: a consent grant that survives an unrelated edit is
    // read on the far side of the lock, so it is the grant still on file rather
    // than one a concurrent revoke has since cleared.
    const granted = { acknowledgedAt: '2026-01-01T00:00:00.000Z', version: 1 };
    applyOnboarding({ vaultConsent: granted }, base);

    applyOnboarding((current) => ({ policy: 'warn', vaultConsent: current.vaultConsent }), base);

    expect(readWorkspaceSettings(base).vaultConsent).toEqual(granted);
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('drops a field the updater returns as undefined', () => {
    applyOnboarding(
      { modelJudgeConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 } },
      base,
    );
    applyOnboarding(() => ({ modelJudgeConsent: undefined }), base);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeUndefined();
  });

  it('does not write when the updater throws', () => {
    applyOnboarding({ policy: 'warn' }, base);
    expect(() =>
      applyOnboarding(() => {
        throw new Error('derivation failed');
      }, base),
    ).toThrow('derivation failed');
    expect(readWorkspaceSettings(base).policy).toBe('warn');
    // And the lock is released, so the next writer is not left waiting it out.
    expect(applyOnboarding({ historicalAccess: 'full' }, base).historicalAccess).toBe('full');
  });
});
