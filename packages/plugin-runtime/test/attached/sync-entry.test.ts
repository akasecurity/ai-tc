import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachedCredential, ControlPlaneConnection } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SYNC_STATE_FILENAME } from '../../src/attached/sync-state.ts';

const getPolicyBundle = vi.fn();

vi.mock('@akasecurity/remote', () => ({
  createRemoteClient: () => ({ getPolicyBundle }),
}));

// The entry resolves a real `~/.aka` layout under a temp root, so the test
// exercises the process wrapper against the same file I/O production uses
// rather than against a mocked layout.
let base: string;

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.example-org.internal',
  attachedAt: '2026-08-19T10:00:00.000Z',
};

const CREDENTIAL: AttachedCredential = {
  specVersion: 1,
  endpoint: 'https://aka.example-org.internal',
  apiKey: 'not-a-real-key-6a1f8e3b7d25',
};

/** Both halves, in the real layout the entry resolves. */
function attach(): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base);
  writeControlPlaneCredential(settingsDirOf(base), CREDENTIAL);
}

const statePath = (): string => join(dataDirOf(base), SYNC_STATE_FILENAME);

beforeEach(() => {
  getPolicyBundle.mockReset();
  base = mkdtempSync(join(tmpdir(), 'aka-entry-home-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

/**
 * The detached child's process wrapper — specifically, WHEN it records anything.
 *
 * The interesting case is the one ordering where a non-attempt becomes visible:
 * SessionStart spawns the child, the user runs `detach` (which clears the
 * attachment and the sync-state file precisely so no stale verdict survives),
 * and only then does the child get as far as reading its configuration. If it
 * writes an outcome at that point it re-creates the file the detach removed,
 * and the next attach opens on a verdict about a plane this machine never
 * called.
 */
describe('runAttachedSync', () => {
  it('records NOTHING when the device was detached before the pull', async () => {
    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base);

    expect(existsSync(statePath())).toBe(false);
    // …and it did not get as far as the network either.
    expect(getPolicyBundle).not.toHaveBeenCalled();
  });

  it('does not RESURRECT a sync-state file that detach just deleted', async () => {
    // The same ordering, staged the way it actually happens: a previous session
    // left state behind, detach removed it, the orphaned child lands last.
    writeFileSync(statePath(), JSON.stringify({ outcome: 'ok', atMs: 1 }), { mode: 0o600 });
    rmSync(statePath());

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base);
    expect(existsSync(statePath())).toBe(false);
  });

  it('records a real attempt, so the guard above is not just "never writes"', async () => {
    // The control. Without it, deleting the write call entirely would pass both
    // cases above while removing the only failure signal `/aka:status` has.
    attach();
    getPolicyBundle.mockRejectedValue(new Error('ECONNREFUSED'));

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base);

    expect(existsSync(statePath())).toBe(true);
    expect(JSON.parse(readFileSync(statePath(), 'utf8'))).toMatchObject({
      outcome: 'unreachable',
    });
  });
});
