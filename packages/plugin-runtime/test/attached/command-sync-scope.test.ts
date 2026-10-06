import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as Remote from '@akasecurity/remote';
import type { ControlPlaneConnection } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CommandScan } from '../../src/attached/command-sync.ts';

// The device-command channel on a SCOPED attachment. A command is serviced only
// from a scan root whose repository is enrolled for this deployment. From any
// other root it is skipped — no scan and NO ACK — so the deployment re-serves
// it and a sync from an enrolled checkout picks it up. Expiry still acks.
//
// THE MODE IS STOOD IN FOR, NOT WRITTEN. While `reader.scoped` is armed, the
// usable v1 credential on disk is reported by the wide credential read as its
// v2 twin, so each case differs from a machine-wide one in the mode alone. How
// the reader treats a v2 file on disk is pinned in @akasecurity/persistence's
// credential suite. Only the network client is faked otherwise; the failure
// classifier stays real.

const pollCommand = vi.fn();
const ackCommand = vi.fn();
const reader = vi.hoisted(() => ({ scoped: false }));

vi.mock('@akasecurity/remote', async (importActual) => ({
  ...(await importActual<typeof Remote>()),
  createRemoteClient: () => ({ pollCommand, ackCommand }),
}));

vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readControlPlaneCredentialFile: (
      ...args: Parameters<typeof actual.readControlPlaneCredentialFile>
    ) => {
      const real = actual.readControlPlaneCredentialFile(...args);
      return real.usable && reader.scoped
        ? { usable: true, credential: { ...real.credential, specVersion: 2, mode: 'scoped' } }
        : real;
    },
  };
});

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.acme.test',
  attachedAt: '2026-09-03T10:00:00.000Z',
};
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';
const COMMAND = {
  id: 'cmd_1',
  kind: 'shares_rescan' as const,
  issuedAt: '2026-09-03T12:00:00.000Z',
  expiresAt: '2026-09-04T12:00:00.000Z',
};
const BEFORE_DEADLINE = () => Date.parse('2026-09-04T11:59:59.000Z');
const AFTER_DEADLINE = () => Date.parse('2026-09-04T12:00:01.000Z');

let base: string;

function attach(scope?: unknown): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base, null);
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint: CONNECTION.endpoint,
    apiKey: TEST_KEY,
  });
  if (scope !== undefined) writeScope(scope);
}

// Raw JSON, so a case can change the scope between two passes exactly as an
// enroll landing between two syncs would.
function writeScope(scope: unknown): void {
  const file = join(settingsDirOf(base), 'settings.json');
  const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  writeFileSync(file, JSON.stringify({ ...settings, attachmentScope: scope }));
}

const enrolled = (...identities: string[]) => ({
  endpoint: CONNECTION.endpoint,
  entries: identities.map((identity) => ({
    kind: 'repo',
    identity,
    enrolledAt: '2026-09-02T10:00:00.000Z',
  })),
});

function scanAt(rootScopeKey: () => string | undefined) {
  const run = vi.fn(() => Promise.resolve({ projects: 1 }));
  const keyOf = vi.fn(rootScopeKey);
  const scan: CommandScan = { rootScopeKey: keyOf, run };
  return { scan, run, keyOf };
}

const deps = (scan: CommandScan, now: () => number = BEFORE_DEADLINE) => ({
  base,
  settingsDir: settingsDirOf(base),
  scan,
  now,
});

beforeEach(() => {
  pollCommand.mockReset();
  ackCommand.mockReset();
  ackCommand.mockResolvedValue(undefined);
  pollCommand.mockResolvedValue(COMMAND);
  reader.scoped = true;
  base = mkdtempSync(join(tmpdir(), 'aka-cmd-scope-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('runCommandSync — a scoped attachment', () => {
  it('skips a command from an unenrolled root: no scan, and NO ack', async () => {
    attach(enrolled(WORK_REPO));
    const { scan, run } = scanAt(() => PERSONAL_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');

    expect(pollCommand).toHaveBeenCalledTimes(1);
    // Not scanned: nothing about the directory is gathered.
    expect(run).not.toHaveBeenCalled();
    // Not acked: nothing about it is said — not even "declined".
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('services the same command once the root is enrolled — the skip is a retry, not an answer', async () => {
    attach(enrolled(WORK_REPO));
    const { scan, run } = scanAt(() => PERSONAL_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');
    // Settings are read on every pass, so an enroll between two syncs counts.
    writeScope(enrolled(WORK_REPO, PERSONAL_REPO));
    await expect(runCommandSync(deps(scan))).resolves.toBe('reported');

    expect(run).toHaveBeenCalledTimes(1);
    expect(ackCommand).toHaveBeenCalledTimes(1);
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', { outcome: 'reported', projectsScanned: 1 });
  });

  it('services a command whose root is enrolled', async () => {
    attach(enrolled(WORK_REPO));
    const { scan, run } = scanAt(() => WORK_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('reported');
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('skips a root with no key — a remoteless checkout or a scratch directory is never enrolled', async () => {
    attach(enrolled(WORK_REPO));
    const { scan, run } = scanAt(() => undefined);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');
    expect(run).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('skips everything while nothing is enrolled', async () => {
    attach();
    const { scan } = scanAt(() => WORK_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('reads a scope built for another deployment as empty', async () => {
    attach({ ...enrolled(WORK_REPO), endpoint: 'https://aka.other.test' });
    const { scan } = scanAt(() => WORK_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('fails closed when the root key cannot be read', async () => {
    attach(enrolled(WORK_REPO));
    const { scan, run } = scanAt(() => {
      throw new Error('unreadable git config');
    });
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');
    expect(run).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('still acks an EXPIRED command from an unenrolled root, and never asks for its key', async () => {
    // Expiry is decided first and says nothing about the directory, so a
    // command past its deadline is declined exactly as it is on any machine.
    attach(enrolled(WORK_REPO));
    const { scan, run, keyOf } = scanAt(() => PERSONAL_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan, AFTER_DEADLINE))).resolves.toBe('failed');
    expect(run).not.toHaveBeenCalled();
    expect(keyOf).not.toHaveBeenCalled();
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'failed',
      reason: 'expired',
      projectsScanned: 0,
    });
  });
});

describe('runCommandSync — a poll that finds nothing', () => {
  it('never asks a scoped attachment for the root key', async () => {
    // The key is read from repository files, so it is asked for only once a
    // command has arrived. The ordinary poll — the one almost every sync makes —
    // finds nothing and must cost no file read.
    attach(enrolled(WORK_REPO));
    pollCommand.mockResolvedValue(null);
    const { scan, run, keyOf } = scanAt(() => WORK_REPO);
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('none');

    expect(pollCommand).toHaveBeenCalledTimes(1);
    expect(keyOf).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });
});

describe('commandScanFor — a session directory that cannot be read', () => {
  // A working directory that was removed under a running session makes
  // `process.cwd()` throw. The scan is built while the sync entry evaluates its
  // arguments, so a throw there would end the whole sync — the policy pull
  // included — where it used to fail only the scan, and say so.
  const unreadableDirectory = () => {
    throw new Error('ENOENT: no such file or directory, uv_cwd');
  };

  async function buildWithUnreadableDirectory() {
    const scanWorktree = vi.fn(() => Promise.resolve({ scanned: 1 }));
    const { commandScanFor } = await import('../../src/attached/command-sync.ts');
    const build = () =>
      commandScanFor({ dataDir: dataDirOf(base) } as never, scanWorktree, SOURCE_TOOL.ClaudeCode);
    const spy = vi.spyOn(process, 'cwd').mockImplementation(unreadableDirectory);
    try {
      // Built twice on purpose: the first asserts the build does not throw, the
      // second is the scan the case then drives.
      expect(build).not.toThrow();
      return { scan: build(), scanWorktree };
    } finally {
      spy.mockRestore();
    }
  }

  it('builds anyway: no key, and a scan that rejects', async () => {
    const { scan, scanWorktree } = await buildWithUnreadableDirectory();

    // No key, so a scoped attachment never services a command from here.
    expect(scan.rootScopeKey()).toBeUndefined();
    // A rejection, so the command channel's own catch acks `scan_failed`.
    await expect(scan.run()).rejects.toThrow();
    expect(scanWorktree).not.toHaveBeenCalled();
  });

  it('acks a machine-wide attachment as scan_failed, exactly as it always has', async () => {
    reader.scoped = false;
    attach();
    const { scan, scanWorktree } = await buildWithUnreadableDirectory();
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('failed');

    expect(scanWorktree).not.toHaveBeenCalled();
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', {
      outcome: 'failed',
      reason: 'scan_failed',
      projectsScanned: 0,
    });
  });

  it('leaves the command for a scoped attachment: no scan, and NO ack', async () => {
    attach(enrolled(WORK_REPO));
    const { scan, scanWorktree } = await buildWithUnreadableDirectory();
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('out-of-scope');

    expect(scanWorktree).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });
});

describe('runCommandSync — a machine-wide attachment', () => {
  it('never asks for the root key, and services the command as before', async () => {
    // Machine-wide forwards everything, so the root's repository files are not
    // read on its behalf — and a key source that would throw cannot cost it a
    // command.
    reader.scoped = false;
    attach();
    const { scan, run, keyOf } = scanAt(() => {
      throw new Error('must not be called');
    });
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('reported');
    expect(keyOf).not.toHaveBeenCalled();
    expect(run).toHaveBeenCalledTimes(1);
  });
});
