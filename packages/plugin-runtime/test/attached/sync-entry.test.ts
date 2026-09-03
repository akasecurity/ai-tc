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
const pollCommand = vi.fn();
const ackCommand = vi.fn();

vi.mock('@akasecurity/remote', () => ({
  createRemoteClient: () => ({ getPolicyBundle, pollCommand, ackCommand }),
}));

/** What the two jobs did, in the order they did it. */
let order: string[];

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
  pollCommand.mockReset();
  ackCommand.mockReset();
  ackCommand.mockResolvedValue(undefined);
  order = [];
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

/**
 * The second job in the same child.
 *
 * `runAttachedSync` grew a device-command pass, and the whole of it — the
 * forwarding of `deps.scan`, the ordering against the policy pull, and the
 * separate catch — was argued in comments and covered by nothing: every case
 * above calls `runAttachedSync(base)` with no `deps`, so `deps.scan` is
 * undefined and `runCommandSync` returns at its first line. Deleting the entire
 * block left the workspace green.
 */
describe('runAttachedSync — the device-command pass', () => {
  const scanning = (): (() => Promise<{ projects: number }>) => () => {
    order.push('scan');
    return Promise.resolve({ projects: 1 });
  };

  it('services a command, so the block is reached at all', async () => {
    attach();
    getPolicyBundle.mockRejectedValue(new Error('ECONNREFUSED'));
    pollCommand.mockResolvedValue({
      id: 'cmd_1',
      kind: 'shares_rescan',
      issuedAt: '2026-09-03T00:00:00.000Z',
      expiresAt: '2026-09-04T00:00:00.000Z',
    });

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base, { scan: scanning() });

    expect(pollCommand).toHaveBeenCalledTimes(1);
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'reported',
      projectsScanned: 1,
    });
  });

  it('does not poll when the host passed no scanner', async () => {
    // The capability rule, asserted on the ENTRY rather than only on
    // `runCommandSync`: a host that cannot scan must not accept work it could
    // never finish, and the entry is what decides whether to hand a scan over.
    attach();
    getPolicyBundle.mockRejectedValue(new Error('ECONNREFUSED'));

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base);

    expect(pollCommand).not.toHaveBeenCalled();
  });

  it('pulls the policy BEFORE it services a command', async () => {
    // The ordering is load-bearing and stated in the source: the scan a command
    // triggers reads the ruleset the pull just cached, so a command serviced
    // first would scan against the previous one. Swap the two statements in
    // `sync-entry.ts` and this is what fails.
    attach();
    getPolicyBundle.mockImplementation(() => {
      order.push('policy');
      return Promise.reject(new Error('ECONNREFUSED'));
    });
    pollCommand.mockImplementation(() => {
      order.push('poll');
      return Promise.resolve(null);
    });

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base, { scan: scanning() });

    expect(order).toEqual(['policy', 'poll']);
  });

  it('still services a command after the policy pull threw', async () => {
    // Two independent jobs sharing one child, not one job in two halves. Merge
    // the two try blocks and a failed pull silently cancels the command channel
    // — a machine that stops taking commands because an unrelated route is
    // down, with nothing anywhere saying so.
    attach();
    getPolicyBundle.mockRejectedValue(new Error('ECONNREFUSED'));
    pollCommand.mockResolvedValue(null);

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await runAttachedSync(base, { scan: scanning() });

    expect(pollCommand).toHaveBeenCalledTimes(1);
  });

  it('keeps the sync state the pull already wrote when the command pass fails', async () => {
    // The other direction of the same split. A command that fails must not cost
    // `/aka:status` the verdict the policy pull had already earned.
    attach();
    getPolicyBundle.mockRejectedValue(new Error('ECONNREFUSED'));
    pollCommand.mockRejectedValue(new Error('ETIMEDOUT'));

    const { runAttachedSync } = await import('../../src/attached/sync-entry.ts');
    await expect(runAttachedSync(base, { scan: scanning() })).resolves.toBeUndefined();

    expect(existsSync(statePath())).toBe(true);
    expect(JSON.parse(readFileSync(statePath(), 'utf8'))).toMatchObject({
      outcome: 'unreachable',
    });
  });
});
