import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { loadConfig } from '@akasecurity/plugin-sdk';
import type * as Remote from '@akasecurity/remote';
import type { ControlPlaneConnection } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CommandScan, WorktreeScan } from '../../src/attached/command-sync.ts';

// The scan a device command runs, and the configuration it runs with. The sync
// child builds the scan when a session spawns it; the command is serviced
// later, after a live read of the settings decided the scan root may be
// scanned. The scan's own forward has to resolve the enrolled scope from that
// same moment, so the configuration is loaded when the scan RUNS — or an
// unenroll that lands between spawn and poll leaves the scan forwarding under
// the scope it was spawned with.
//
// The credential on disk is real (a v2 file for the scoped cases), and so are
// the settings the plugin's own loader reads. Only the network client is faked.

const pollCommand = vi.fn();
const ackCommand = vi.fn();

vi.mock('@akasecurity/remote', async (importActual) => ({
  ...(await importActual<typeof Remote>()),
  createRemoteClient: () => ({ pollCommand, ackCommand }),
}));

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.acme.test',
  attachedAt: '2026-09-03T10:00:00.000Z',
};
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const NESTED_REPO = 'github.com/acme/billing-sdk';
const COMMAND = {
  id: 'cmd_1',
  kind: 'shares_rescan' as const,
  issuedAt: '2026-09-03T12:00:00.000Z',
  expiresAt: '2026-09-04T12:00:00.000Z',
};
const BEFORE_DEADLINE = () => Date.parse('2026-09-04T11:59:59.000Z');

let base: string;

function attach(mode: 'machine' | 'scoped', scope?: unknown): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base, null);
  writeControlPlaneCredential(
    settingsDirOf(base),
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: CONNECTION.endpoint, apiKey: TEST_KEY }
      : { specVersion: 1, endpoint: CONNECTION.endpoint, apiKey: TEST_KEY },
  );
  if (scope !== undefined) writeScope(scope);
}

// Raw JSON, so a case can change the scope between spawn and poll exactly as an
// enroll or unenroll landing there would.
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

/**
 * A checkout whose origin is `https://github.com/<slug>.git`, keyed `github.com/<slug>`. One per
 * case, under that case's own `base`, so the per-directory memo behind the key cannot hand one case
 * another's answer.
 */
function checkout(slug: string): string {
  const dir = join(base, 'checkout');
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    `[remote "origin"]\n\turl = https://github.com/${slug}.git\n`,
  );
  return dir;
}

/** Build the scan the way a sync child does when it spawns: from inside `dir`. */
async function buildIn(
  dir: string,
  load: () => PluginConfig,
  scanWorktree: WorktreeScan,
): Promise<CommandScan> {
  const { commandScanFor } = await import('../../src/attached/command-sync.ts');
  const spy = vi.spyOn(process, 'cwd').mockReturnValue(dir);
  try {
    return commandScanFor(load, scanWorktree, SOURCE_TOOL.ClaudeCode);
  } finally {
    spy.mockRestore();
  }
}

const deps = (scan: CommandScan) => ({
  base,
  settingsDir: settingsDirOf(base),
  scan,
  now: BEFORE_DEADLINE,
});

beforeEach(() => {
  pollCommand.mockReset();
  ackCommand.mockReset();
  ackCommand.mockResolvedValue(undefined);
  pollCommand.mockResolvedValue(COMMAND);
  base = mkdtempSync(join(tmpdir(), 'aka-cmd-live-config-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('commandScanFor loads its configuration when the scan runs', () => {
  it('does not load the configuration when the scan is built, and loads it once per run', async () => {
    const repo = checkout('acme/payments-api');
    const load = vi.fn(() => ({ dataDir: 'at-run' }) as never);
    const seen: unknown[] = [];
    const scanWorktree: WorktreeScan = (config) => {
      seen.push(config);
      return Promise.resolve({ scanned: 1 });
    };

    const scan = await buildIn(repo, load, scanWorktree);
    expect(load).not.toHaveBeenCalled();

    await expect(scan.run()).resolves.toEqual({ projects: 1 });
    expect(load).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([{ dataDir: 'at-run' }]);
  });

  it('hands the scan the configuration in force when it runs, not when it was built', async () => {
    const repo = checkout('acme/payments-api');
    let current = 'at-build';
    const seen: string[] = [];
    const scan = await buildIn(
      repo,
      () => ({ dataDir: current }) as never,
      (config) => {
        seen.push(config.dataDir);
        return Promise.resolve({ scanned: 1 });
      },
    );

    current = 'at-run';
    await scan.run();

    expect(seen).toEqual(['at-run']);
  });

  it('builds even when the configuration cannot be loaded, and the run rejects', async () => {
    // The scan is built while a sync entry evaluates its arguments, so a throw
    // there would end the whole sync, the policy pull included. A loader that
    // fails costs the scan alone, which the command channel acks as failed.
    const { commandScanFor } = await import('../../src/attached/command-sync.ts');
    const load = (): never => {
      throw new Error('settings unreadable');
    };
    const scanWorktree = vi.fn<WorktreeScan>(() => Promise.resolve({ scanned: 1 }));

    expect(() => commandScanFor(load, scanWorktree, SOURCE_TOOL.ClaudeCode)).not.toThrow();
    const scan = commandScanFor(load, scanWorktree, SOURCE_TOOL.ClaudeCode);

    await expect(scan.run()).rejects.toThrow(/settings unreadable/);
    expect(scanWorktree).not.toHaveBeenCalled();
  });
});

describe('runCommandSync on a scoped attachment, after an unenroll', () => {
  it('forwards the serviced scan under the scope in force when the command is serviced', async () => {
    const repo = checkout('acme/payments-api');
    attach('scoped', enrolled(WORK_REPO, NESTED_REPO));
    const seen: unknown[] = [];
    const scanWorktree: WorktreeScan = (config) => {
      seen.push(config.settings.attachmentScope);
      return Promise.resolve({ scanned: 1 });
    };
    const scan = await buildIn(repo, () => loadConfig(base), scanWorktree);

    // A nested repository is unenrolled after the sync child spawned and before
    // it polls. The scan root itself stays enrolled, so the command is serviced.
    writeScope(enrolled(WORK_REPO));
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('reported');

    expect(seen).toEqual([enrolled(WORK_REPO)]);
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', { outcome: 'reported', projectsScanned: 1 });
  });
});

describe('runCommandSync on a machine-wide attachment', () => {
  it('services the command as before, with the configuration loaded once, at run time', async () => {
    const repo = checkout('acme/payments-api');
    attach('machine');
    const load = vi.fn(() => loadConfig(base));
    const scanWorktree = vi.fn<WorktreeScan>(() => Promise.resolve({ scanned: 1 }));
    const scan = await buildIn(repo, load, scanWorktree);
    expect(load).not.toHaveBeenCalled();
    const { runCommandSync } = await import('../../src/attached/command-sync.ts');

    await expect(runCommandSync(deps(scan))).resolves.toBe('reported');

    expect(load).toHaveBeenCalledTimes(1);
    expect(scanWorktree).toHaveBeenCalledTimes(1);
    expect(scanWorktree.mock.calls[0]?.[0]).toBe(load.mock.results[0]?.value);
    expect(scanWorktree.mock.calls[0]?.[1]).toEqual({
      sourceTool: SOURCE_TOOL.ClaudeCode,
      rootDir: repo,
    });
  });
});
