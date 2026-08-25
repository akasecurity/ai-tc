// Tests the store-health module directly — NEVER via the hook entry files
// (src/hooks/*.ts run main() on import and hang vitest collection). Identical
// to plugins/claude-code/src/hooks/store-health.test.ts — no harness-specific
// logic here.
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir as dataDirOf } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeRedirectedMessage,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from '../../src/hooks/store-health.ts';

function configFor(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: join(dataDir, 'settings'),
    onboarded: false,
    provider: { provider: 'openai' },
  };
}

describe('openGatewayOrNull — observable store-open failure', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-health-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns null when aka.db is not a database (corrupt bytes)', () => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');

    expect(openGatewayOrNull(configFor(dir))).toBeNull();
  });

  it('returns a working gateway for a healthy (fresh) data dir', async () => {
    const gateway = openGatewayOrNull(configFor(dir));
    expect(gateway).not.toBeNull();
    await gateway?.close();
  });
});

describe('claimStoreUnavailableWarning — once per session', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-warn-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('warns on the first claim of a session, then stays quiet for that session', () => {
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(false);
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(false);
  });

  it('a NEW session warns again (single overwritten marker, not an accumulating set)', () => {
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'sess-2')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'sess-2')).toBe(false);
  });

  it('with no session id it cannot dedupe and always warns', () => {
    expect(claimStoreUnavailableWarning(dir, undefined)).toBe(true);
    expect(claimStoreUnavailableWarning(dir, undefined)).toBe(true);
  });
});

describe('storeUnavailableMessage', () => {
  it('names the store path, says detection is off, and stays fail-open in tone', () => {
    const message = storeUnavailableMessage('/home/u/.aka/data/aka.db');
    expect(message).toContain('/home/u/.aka/data/aka.db');
    expect(message).toContain('OFF for this session');
    expect(message).toContain('fails open');
  });
});

// A symlinked store path is the OTHER way a session looks protected while it is
// not what the user thinks: everything is scanned and recorded, but into someone
// else's directory, under permissions AKA never applied. The store opens fine, so
// the unavailable-store warning above can never reach it.
describe('warnIfStoreRedirected — a symlinked store path is surfaced', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-redirect-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // The home is derived from `dataDir` because PluginConfig carries the leaves
  // and not the base. If the layout ever stops putting data/ directly under the
  // base, this is the assertion that says so — without it the derivation would
  // silently start reporting the wrong directory, i.e. no directory at all.
  it('derives the store home from dataDir exactly as the layout builds it', () => {
    const home = join(dir, 'somewhere');
    expect(dataDirOf(home)).toBe(join(home, 'data'));
  });

  it('says nothing at all when no store path is a symlink', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const home = join(dir, 'real-home');
    mkdirSync(dataDirOf(home), { recursive: true });
    const written: string[] = [];
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    expect(written).toEqual([]);
  });

  it('warns once per session, naming the target and its non-owner-only mode', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const victim = join(dir, 'victim');
    mkdirSync(victim, { mode: 0o755 });
    const home = join(dir, 'linked-home');
    symlinkSync(victim, home);
    mkdirSync(dataDirOf(home), { recursive: true });

    const written: string[] = [];
    const config = configFor(dataDirOf(home));
    warnIfStoreRedirected(config, 's1', (m) => written.push(m));

    expect(written).toHaveLength(1);
    const message = written[0] ?? '';
    // The link, where it really lands, and the permission the store inherits —
    // the three facts nothing else on the plugin path can tell the user.
    expect(message).toContain(home);
    expect(message).toContain(realpathSync(victim));
    expect(message).toContain('0755');
    expect(message).toContain('NOT owner-only');

    // Same session → silent. A per-hook warning would fire on every tool call.
    warnIfStoreRedirected(config, 's1', (m) => written.push(m));
    expect(written).toHaveLength(1);

    // A new session is told again: the condition is still true, and the marker
    // is one overwritten file rather than an accumulating set.
    warnIfStoreRedirected(config, 's2', (m) => written.push(m));
    expect(written).toHaveLength(2);
  });

  it('never throws on a hostile home — the warning is advisory, the hook is not', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // A store path whose link resolves NOWHERE: nothing to stat, nothing to
    // create through, and the marker write below it cannot land either.
    const home = join(dir, 'dangling-home');
    mkdirSync(home);
    symlinkSync(join(dir, 'no-such-volume'), join(home, 'data'));
    const written: string[] = [];
    expect(() => {
      warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    }).not.toThrow();
    // It is still REPORTED — a link that resolves nowhere is exactly the state a
    // user needs told about, and reporting nothing here would read as healthy.
    expect(written).toHaveLength(1);
    expect(written[0] ?? '').toContain('does not exist');

    // …and STILL only once. data/ is unwritable here, so the marker cannot land
    // in its natural home; without the fallback candidate the claim is never
    // recorded and every later hook fire in the session warns again — a fresh
    // multi-line warning on every tool call, in the very configuration this
    // feature exists to report. Driving it a second and third time is the whole
    // point: calling once cannot tell a working dedupe from an absent one.
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    expect(written).toHaveLength(1);

    // A different session is still told, so the fallback dedupes rather than
    // silences.
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's2', (m) => written.push(m));
    expect(written).toHaveLength(2);
  });
});

describe('storeRedirectedMessage', () => {
  it('reports an owner-only target without the "NOT owner-only" claim', () => {
    const message = storeRedirectedMessage([
      {
        path: '/home/u/.aka',
        target: '/mnt/other',
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: 0o700,
      },
    ]);
    expect(message).toContain('0700');
    expect(message).not.toContain('NOT owner-only');
    // The redirection is still the story even when the mode is fine.
    expect(message).toContain('/mnt/other');
  });

  it('does not claim a write or an inherited mode when the link resolves NOWHERE', () => {
    // Nothing has been written and nothing inherited, so both of the framing
    // clauses would be false — the same three-shapes reasoning `symlinkWarnings`
    // records, applied to the one-line form.
    const message = storeRedirectedMessage([
      {
        path: '/home/u/.aka/keys',
        target: '/no/such/volume',
        holds: 'the vault key',
        missing: true,
        mode: undefined,
      },
    ]);
    expect(message).toContain('does not exist');
    expect(message).toContain('cannot write there');
    expect(message).not.toContain('writing into the target instead');
    expect(message).not.toContain('keeps whatever the target already had');
  });

  it('drops the permissions clause on Windows, where no mode is ever applied', () => {
    const path = {
      path: 'C:\\Users\\u\\.aka',
      target: 'D:\\elsewhere',
      holds: 'the store (including the prompt corpus in aka.db)',
      missing: false,
      mode: undefined,
    };
    // The redirection still stands on Windows — a junction needs no elevation —
    // but claiming the target's permissions are kept describes a control that
    // platform does not have.
    expect(storeRedirectedMessage([path], 'win32')).not.toContain(
      'keeps whatever the target already had',
    );
    expect(storeRedirectedMessage([path], 'win32')).toContain('writing into the target instead');
    // …and the POSIX branch still carries it.
    expect(storeRedirectedMessage([path], 'linux')).toContain(
      'keeps whatever the target already had',
    );
  });

  it('counts the paths it lists rather than always saying "a store path"', () => {
    const one = {
      path: '/home/u/.aka',
      target: '/mnt/a',
      holds: 'the store (including the prompt corpus in aka.db)',
      missing: false,
      mode: 0o700,
    };
    const two = { ...one, path: '/home/u/.aka/keys', target: '/mnt/b', holds: 'the vault key' };
    expect(storeRedirectedMessage([one], 'linux')).toContain('a store path is a symlink');
    const both = storeRedirectedMessage([one, two], 'linux');
    expect(both).toContain('2 store paths are symlinks');
    expect(both).toContain('/mnt/a');
    expect(both).toContain('/mnt/b');
  });

  it('reports no mode at all when there is none to inherit (Windows, or no target)', () => {
    const message = storeRedirectedMessage([
      {
        path: 'C:\\Users\\u\\.aka',
        target: 'D:\\elsewhere',
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: undefined,
      },
    ]);
    expect(message).toContain('D:\\elsewhere');
    // An absent mode must never be rendered as a safe one.
    expect(message).not.toContain('0700');
    expect(message).not.toContain('NOT owner-only');
  });
});
