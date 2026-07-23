// Tests the store-health module directly — NEVER via the hook entry files
// (src/hooks/*.ts run main() on import and hang vitest collection).
//
// What this pins: a store-open failure (corrupt aka.db) must be OBSERVABLE by
// the adapters — openGatewayOrNull returns null instead of throwing — so the
// hooks can keep allowing (fail-open) while telling the user, once per
// session, that nothing is being scanned. Before this seam existed, a corrupt
// store silently disabled all detection while the onboarding nudge still
// claimed AKA was monitoring.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
} from '../../src/hooks/store-health.ts';

function configFor(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: join(dataDir, 'settings'),
    onboarded: false,
    provider: { provider: 'anthropic' },
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
