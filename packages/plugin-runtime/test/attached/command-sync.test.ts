/**
 * The device half of the device-command channel.
 *
 * The cases below are about what this module REFUSES to do, because that is
 * where its value is. A deployment tells a machine a verb; the machine chooses
 * its own scan scope; a machine that cannot scan does not accept work it can
 * never finish; and every terminal path acks, so an operator's roster never has
 * to distinguish "failed" from "switched off" by waiting a day.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachedCredential, ControlPlaneConnection } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DiscoverScan } from '../../src/attached/command-sync.ts';

const pollCommand = vi.fn();
const ackCommand = vi.fn();

vi.mock('@akasecurity/remote', () => ({
  createRemoteClient: () => ({ pollCommand, ackCommand }),
}));

let base: string;

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.example-org.internal',
  attachedAt: '2026-09-03T10:00:00.000Z',
};

const CREDENTIAL: AttachedCredential = {
  specVersion: 1,
  endpoint: 'https://aka.example-org.internal',
  apiKey: 'not-a-real-key-6a1f8e3b7d25',
};

const COMMAND = {
  id: 'cmd_1',
  kind: 'shares_rescan' as const,
  issuedAt: '2026-09-03T12:00:00.000Z',
  expiresAt: '2026-09-04T12:00:00.000Z',
};

function attach(): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base);
  writeControlPlaneCredential(settingsDirOf(base), CREDENTIAL);
}

const deps = (scan?: () => Promise<{ projects: number }>) => ({
  base,
  settingsDir: settingsDirOf(base),
  ...(scan === undefined ? {} : { scan }),
});

beforeEach(() => {
  pollCommand.mockReset();
  ackCommand.mockReset();
  ackCommand.mockResolvedValue(undefined);
  base = mkdtempSync(join(tmpdir(), 'aka-cmd-home-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('runCommandSync', () => {
  it('does not poll at all on a host that cannot scan', async () => {
    // The browser extension's native host. Accepting a command it could never
    // run would leave it outstanding on the roster until it expired — which an
    // operator reads as a machine that is switched off.
    attach();
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps())).resolves.toBeNull();
    expect(pollCommand).not.toHaveBeenCalled();
  });

  it('does not poll on a machine that is not attached', async () => {
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');
    await expect(runCommandSync(deps(() => Promise.resolve({ projects: 1 })))).resolves.toBeNull();
    expect(pollCommand).not.toHaveBeenCalled();
  });

  it('reports nothing pending without scanning', async () => {
    attach();
    pollCommand.mockResolvedValue(null);
    const scan = vi.fn(() => Promise.resolve({ projects: 1 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('none');
    expect(scan).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('distinguishes "nothing to forward" from a scan that reported nothing', async () => {
    // Not `reported` with a count of zero: an operator acts differently on
    // "this machine has no projects here" than on "it scanned and sent none",
    // and the roster styles them differently — which is only possible if the
    // device says which one happened.
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(() => Promise.resolve({ projects: 0 })))).resolves.toBe(
      'failed',
    );
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'failed',
      reason: 'no_projects',
      projectsForwarded: 0,
    });
  });

  it('scans and acks the project count it actually forwarded', async () => {
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(() => Promise.resolve({ projects: 3 })))).resolves.toBe('reported');
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'reported',
      projectsForwarded: 3,
    });
  });

  /**
   * The load-bearing one. A device that scans, fails, and says nothing is
   * indistinguishable on the roster from a device that is off — and the
   * operator learns nothing for 24 hours, until the command expires.
   */
  it('acks a FAILURE rather than going quiet', async () => {
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(
      runCommandSync(
        deps(() => {
          throw new Error('EACCES /Users/someone/private');
        }),
      ),
    ).resolves.toBe('failed');

    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'failed',
      reason: 'scan_failed',
      projectsForwarded: 0,
    });
  });

  it('never puts the scan error text on the wire', async () => {
    // The closed reason enum is what keeps device-supplied text off an
    // operator's screen. Asserted on the BODY rather than trusting the enum,
    // because the failure this guards against is someone widening the ack to
    // carry a message.
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const secret = 'EACCES /Users/someone/.ssh/id_ed25519';
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await runCommandSync(
      deps(() => {
        throw new Error(secret);
      }),
    );

    expect(JSON.stringify(ackCommand.mock.calls)).not.toContain('EACCES');
    expect(JSON.stringify(ackCommand.mock.calls)).not.toContain('.ssh');
  });

  it('does not scan when the poll itself fails', async () => {
    attach();
    pollCommand.mockRejectedValue(new Error('ECONNREFUSED'));
    const scan = vi.fn(() => Promise.resolve({ projects: 1 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('unreachable');
    expect(scan).not.toHaveBeenCalled();
  });

  /**
   * A command carrying a path fails to parse in the transport, which surfaces
   * here as a rejected poll. The point of the case is what does NOT happen: no
   * scan runs. A command this build refuses to understand must not be serviced
   * on a best-effort reading of the parts it did recognise.
   */
  it('scans nothing when the deployment sent a command it refuses to parse', async () => {
    attach();
    pollCommand.mockRejectedValue(
      Object.assign(new Error('a body this client cannot read'), {
        name: 'RemoteResponseInvalid',
      }),
    );
    const scan = vi.fn(() => Promise.resolve({ projects: 1 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('unreachable');
    expect(scan).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('reports a lost ack as unreachable, not as a success', async () => {
    // The scan happened, but from the deployment's side this device is still
    // outstanding. Claiming 'reported' here would make this return value
    // disagree with the roster it feeds.
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    ackCommand.mockRejectedValue(new Error('ETIMEDOUT'));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(() => Promise.resolve({ projects: 2 })))).resolves.toBe('unreachable');
  });
});

describe('commandScanFor', () => {
  it('chooses its own scope and never accepts one', async () => {
    // The command carries no path — `DeviceCommand.strict()` guarantees that —
    // and this is the other half: the scope handed to the scanner is built here
    // from the process, never from anything that arrived on the wire.
    let seen: { searchRoots: string[] } | null = null;
    const scanAllRepos: DiscoverScan = (_config, opts) => {
      seen = opts;
      return Promise.resolve({ repos: [{}, {}] });
    };
    const { commandScanFor } = await import('../../src/attached/command-sync.ts');

    const scan = commandScanFor(
      { dataDir: dataDirOf(base) } as never,
      scanAllRepos,
      SOURCE_TOOL.ClaudeCode,
    );
    await expect(scan()).resolves.toEqual({ projects: 2 });

    const opts = seen as unknown as { searchRoots: string[] };
    expect(opts.searchRoots).toEqual([process.cwd()]);
    // Never the home directory implicitly — the interactive scan's own rule,
    // and a server-issued command gets the unprivileged half of it. Asserted
    // against the real home rather than a fixture, because the whole claim is
    // about what this scope is NOT.
    expect(opts.searchRoots).not.toContain(homedir());
  });
});
