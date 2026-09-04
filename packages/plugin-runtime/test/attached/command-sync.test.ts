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

import type { WorktreeScan } from '../../src/attached/command-sync.ts';

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

// Relative to the real clock, not a hardcoded pair of instants: most cases
// below call deps(scan) with no `now`, so runCommandSync falls back to the
// real wall clock against this fixture's own expiresAt. A future absolute
// date goes stale the moment the calendar catches up to it.
const COMMAND = {
  id: 'cmd_1',
  kind: 'shares_rescan' as const,
  issuedAt: new Date(Date.now() - 3_600_000).toISOString(),
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
};

function attach(): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base);
  writeControlPlaneCredential(settingsDirOf(base), CREDENTIAL);
}

/** Fixed instants either side of COMMAND's own `expiresAt`. */
const BEFORE_DEADLINE = () => Date.parse(COMMAND.expiresAt) - 1_000;
const AFTER_DEADLINE = () => Date.parse(COMMAND.expiresAt) + 1_000;

// The clock DEFAULTS rather than falling through to the ambient one, because
// `runCommandSync` reads `deps.now ?? Date.now` and COMMAND carries a fixed
// `expiresAt`. Omitting it therefore dated the case rather than leaving it
// clock-free: every test here that serviced COMMAND passed until the wall clock
// reached 2026-09-04T12:00:00Z and then failed for good, on a diff that could
// not touch it — and it failed as `expired`, which reads as a behaviour change
// in the code under test rather than as a stale fixture. A test that wants the
// far side of the deadline says so with AFTER_DEADLINE, so the two directions
// are both explicit and neither depends on when the suite runs.
const deps = (scan?: () => Promise<{ projects: number }>, now: () => number = BEFORE_DEADLINE) => ({
  base,
  settingsDir: settingsDirOf(base),
  ...(scan === undefined ? {} : { scan }),
  now,
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
      projectsScanned: 0,
    });
  });

  it('scans and acks the project count it actually forwarded', async () => {
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(() => Promise.resolve({ projects: 3 })))).resolves.toBe(
      'reported',
    );
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'reported',
      projectsScanned: 3,
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
      projectsScanned: 0,
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

    // POSITIVE CONTROL first. Both assertions below run against
    // `JSON.stringify(ackCommand.mock.calls)`, and an ack that never happened
    // stringifies to `'[]'` — which contains neither string, so the pair would
    // pass on a broken ack path rather than on a safe one.
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'failed',
      reason: 'scan_failed',
      projectsScanned: 0,
    });
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

    await expect(runCommandSync(deps(() => Promise.resolve({ projects: 2 })))).resolves.toBe(
      'unreachable',
    );
  });
});

describe('commandScanFor', () => {
  // The scope is the privilege, so these drive the adapter directly rather than
  // through `runCommandSync`: what matters is the exact options object handed to
  // the scanner, and only a fake standing in for the scanner can see it.
  it('scans ONE worktree at the session cwd, never a discovery sweep', async () => {
    // The command carries no path — `DeviceCommand.strict()` guarantees that —
    // and this is the other half: the scope handed to the scanner is built here
    // from the process, never from anything that arrived on the wire.
    //
    // Asserted as the WHOLE options object rather than field by field, because
    // the defect this replaced was a field that was never passed: the adapter
    // called `scanAllRepos`, whose `maxDepth` defaults to 4, so it swept every
    // repository under the cwd while every comment around it said one project.
    // A per-field assertion cannot see an option that is absent; an exact
    // object can.
    let seen: unknown = null;
    const scanWorktree: WorktreeScan = (_config, opts) => {
      seen = opts;
      return Promise.resolve({ scanned: 4 });
    };
    const { commandScanFor } = await import('../../src/attached/command-sync.ts');

    const scan = commandScanFor(
      { dataDir: dataDirOf(base) } as never,
      scanWorktree,
      SOURCE_TOOL.ClaudeCode,
    );
    await expect(scan()).resolves.toEqual({ projects: 1 });

    // EXACT: a `searchRoots` or a `maxDepth` appearing here is the sweep coming
    // back, and `toEqual` is what fails on it.
    expect(seen).toEqual({ sourceTool: SOURCE_TOOL.ClaudeCode, rootDir: process.cwd() });
  });

  it('reports one project when the worktree held something, zero when it did not', async () => {
    // `no_projects` is a distinct outcome an operator acts on, so the count has
    // to distinguish "scanned an empty worktree" from "scanned a real one". Both
    // directions, because a hardcoded 1 or a hardcoded 0 each satisfies one.
    const { commandScanFor } = await import('../../src/attached/command-sync.ts');
    const config = { dataDir: dataDirOf(base) } as never;

    const found: WorktreeScan = () => Promise.resolve({ scanned: 1 });
    const empty: WorktreeScan = () => Promise.resolve({ scanned: 0 });

    await expect(commandScanFor(config, found, SOURCE_TOOL.ClaudeCode)()).resolves.toEqual({
      projects: 1,
    });
    await expect(commandScanFor(config, empty, SOURCE_TOOL.ClaudeCode)()).resolves.toEqual({
      projects: 0,
    });
  });

  it('scans the session cwd even when that cwd is the home directory', async () => {
    // The old comment here claimed the scope is "never the home directory
    // implicitly" and asserted it with `not.toContain(homedir())` — which was
    // entailed by the test runner's own cwd rather than by anything the code
    // did, and went red against a correct implementation if vitest ran from
    // $HOME. There is no home check and there does not need to be one: the
    // bound is the MODE. `scanWorktree` on $HOME scans that one directory,
    // where the discovery sweep would have walked four levels of it.
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(homedir());
    try {
      let seen: unknown = null;
      const scanWorktree: WorktreeScan = (_config, opts) => {
        seen = opts;
        return Promise.resolve({ scanned: 0 });
      };
      const { commandScanFor } = await import('../../src/attached/command-sync.ts');

      await commandScanFor(
        { dataDir: dataDirOf(base) } as never,
        scanWorktree,
        SOURCE_TOOL.ClaudeCode,
      )();

      expect(seen).toEqual({ sourceTool: SOURCE_TOOL.ClaudeCode, rootDir: homedir() });
    } finally {
      spy.mockRestore();
    }
  });
});

describe('runCommandSync — a command past its own deadline', () => {
  it('declines an EXPIRED command without scanning, and says so', async () => {
    // A laptop closed on Friday and opened the following week is the case this
    // exists for. The deployment is the authority on expiry and is expected not
    // to serve one past its deadline; this is the device declining if it does.
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const scan = vi.fn(() => Promise.resolve({ projects: 3 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan, AFTER_DEADLINE))).resolves.toBe('failed');

    // Not scanned — the whole point is that stale work is not done.
    expect(scan).not.toHaveBeenCalled();
    // …and ACKED anyway, because going quiet reads on a roster exactly like a
    // machine that is switched off.
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'failed',
      reason: 'expired',
      projectsScanned: 0,
    });
  });

  it('services a command that has NOT expired yet', async () => {
    // The positive control. Without it, a `hasExpired` stuck at `true` would
    // satisfy the case above and nothing would ever be scanned again.
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    const scan = vi.fn(() => Promise.resolve({ projects: 1 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan, BEFORE_DEADLINE))).resolves.toBe('reported');
    expect(scan).toHaveBeenCalledTimes(1);
  });

  it('services a command whose deadline cannot be read, rather than refusing it', async () => {
    // FAIL-OPEN on an unreadable stamp, deliberately. `expiresAt` is
    // `printable(64)` on the wire rather than a validated datetime — tightening
    // it is not available, because that field rides the same envelope as the id
    // and a rejected envelope leaves the device unable to ack what it refused.
    // So a deployment that changes its timestamp format must not silently stop
    // every device in the fleet from working.
    attach();
    pollCommand.mockResolvedValue({ ...COMMAND, expiresAt: 'next Tuesday' });
    const scan = vi.fn(() => Promise.resolve({ projects: 1 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan, AFTER_DEADLINE))).resolves.toBe('reported');
    expect(scan).toHaveBeenCalledTimes(1);
  });
});

describe('runCommandSync — a refusal is not an outage', () => {
  // Collapsing a 401 into `unreachable` said "try again" about the one outcome
  // that will never succeed on its own: a revoked key polled every fifteen
  // minutes forever, reported as an outage. `classifyFailure` is the same
  // function `runPolicySync` uses, so the two halves of attached mode cannot
  // reach different verdicts about one refusal.
  const refusal = (status: number): Error & { status: number } =>
    Object.assign(new Error('refused'), { status });

  it.each([
    [401, 'unauthorized'],
    [403, 'forbidden'],
    [500, 'unreachable'],
  ] as const)('classifies a %d on the POLL as %s', async (status, outcome) => {
    attach();
    pollCommand.mockRejectedValue(refusal(status));
    const scan = vi.fn(() => Promise.resolve({ projects: 1 }));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe(outcome);
    expect(scan).not.toHaveBeenCalled();
  });

  it.each([
    [401, 'unauthorized'],
    [403, 'forbidden'],
    [500, 'unreachable'],
  ] as const)('classifies a %d on the ACK as %s', async (status, outcome) => {
    // The ack is a request like any other: a credential refusal is terminal
    // wherever it lands. It is still never the scan's own outcome — from the
    // deployment's side this device remains outstanding.
    attach();
    pollCommand.mockResolvedValue(COMMAND);
    ackCommand.mockRejectedValue(refusal(status));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(
      runCommandSync(deps(() => Promise.resolve({ projects: 1 }), BEFORE_DEADLINE)),
    ).resolves.toBe(outcome);
  });
});
