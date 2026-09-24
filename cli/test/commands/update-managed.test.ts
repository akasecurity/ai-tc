import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import type { ComponentStatus, UpdateReport } from '@akasecurity/schema';
import { MANAGED_PLUGIN_ADVICE } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// `aka update` and `aka check-updates` on a machine where an organization's
// managed settings installed the Claude Code plugin.
//
// The report never offers such a row as an update. These cases hold the two
// commands to that: nothing is applied for it, `check-updates` does not count
// it toward "run `aka update`", an explicit `aka update claude-code` is
// refused rather than run, and `--channel` for it does not hand the user the
// marketplace recipe that would re-register the organization's marketplace
// without its pin.
//
// Every spawning seam is recorded rather than stubbed silently. The PATH shims
// in this repo fail OPEN, so an unstubbed apply here would resolve the
// developer's own `claude` and run a real plugin update.
const seams = vi.hoisted(
  (): {
    report: UpdateReport;
    managed: LocalOps.ManagedInstallLookup | null;
    cliApplied: number;
    pluginApplied: string[];
    pluginResult: LocalOps.ApplyResult;
  } => ({
    report: { statuses: [], availablePlugins: [] },
    managed: null,
    cliApplied: 0,
    pluginApplied: [],
    pluginResult: { ok: true, output: '' },
  }),
);

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    gatherReportLive: (): UpdateReport => seams.report,
    cliVersion: (): string => '0.9.13',
    managedPluginInstall: (): LocalOps.ManagedInstallLookup | null => seams.managed,
    // The CLI's own install channel: a synthetic npm global, so the real plan
    // builder produces a runnable plan and the CLI row reaches its apply.
    detectInstallChannel: (): LocalOps.InstallChannel => ({
      kind: 'global',
      manager: 'npm',
      root: '/opt/node',
      packageDir: '/opt/node/lib/node_modules/@akasecurity/cli',
    }),
    applyCliUpdate: (): LocalOps.ApplyResult => {
      seams.cliApplied += 1;
      return { ok: true, output: '' };
    },
    applyPluginUpdate: (id: string): LocalOps.ApplyResult => {
      seams.pluginApplied.push(id);
      return seams.pluginResult;
    },
    // The host binary is reported present, so a plugin row that IS offered
    // reaches the recorded apply above instead of stopping at a PATH probe that
    // answers differently on a runner with no `claude` installed.
    createCliPluginManager: (
      ...args: Parameters<typeof actual.createCliPluginManager>
    ): LocalOps.CliPluginManager => ({
      ...actual.createCliPluginManager(...args),
      available: () => true,
    }),
  };
});

const { managedUpdateRefusal } = await import('@akasecurity/local-ops');
const { runUpdate } = await import('../../src/commands/update.ts');
const { runCheckUpdates } = await import('../../src/commands/check-updates.ts');

const cliRow = (over: Partial<ComponentStatus> = {}): ComponentStatus => ({
  id: 'cli',
  name: 'aka CLI',
  kind: 'cli',
  installed: '0.9.13',
  latest: '0.9.13',
  updateAvailable: false,
  ...over,
});

/** The Claude Code row as the report builds it for a managed install. */
const managedRow = (over: Partial<ComponentStatus> = {}): ComponentStatus => ({
  id: 'claude-code',
  name: 'Claude Code',
  kind: 'plugin',
  installed: '0.9.13',
  latest: '0.9.14',
  updateAvailable: false,
  managedInstall: { ref: 'fleet-v8', pending: true },
  ...over,
});

let home: string;

beforeEach(() => {
  seams.report = { statuses: [], availablePlugins: [] };
  seams.managed = null;
  seams.cliApplied = 0;
  seams.pluginApplied = [];
  seams.pluginResult = { ok: true, output: '' };
  // A home with no data directory, so `check-updates` writes no cache.
  home = mkdtempSync(join(tmpdir(), 'aka-update-managed-'));
  process.exitCode = undefined;
});

async function capture(body: () => unknown): Promise<{ out: string; err: string; code: number }> {
  let out = '';
  let err = '';
  const outSpy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  const errSpy = vi
    .spyOn(process.stderr, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  try {
    await body();
  } finally {
    outSpy.mockRestore();
    errSpy.mockRestore();
  }
  const code = Number(process.exitCode ?? 0);
  process.exitCode = undefined;
  return { out, err, code };
}

const update = (argv: string[]) => capture(() => runUpdate([...argv, '--home', home]));
const checkUpdates = () =>
  capture(() => {
    runCheckUpdates(['--home', home]);
  });

describe('aka check-updates — a managed install', () => {
  it('does not count it toward `aka update`', async () => {
    seams.report = { statuses: [cliRow(), managedRow()], availablePlugins: [] };

    const { out } = await checkUpdates();

    // The positive control: the managed row was rendered and explained.
    expect(out).toContain('Managed by your organization:');
    expect(out).toContain(MANAGED_PLUGIN_ADVICE);
    expect(out).not.toContain('update(s) available');
    expect(out).not.toContain('Everything is up to date');
    expect(out).toContain('Nothing for `aka update` to apply');
  });

  it('counts only what `aka update` can apply when both are behind', async () => {
    seams.report = {
      statuses: [cliRow({ latest: '0.9.14', updateAvailable: true }), managedRow()],
      availablePlugins: [],
    };

    const { out } = await checkUpdates();

    expect(out).toContain('1 update(s) available — run `aka update` to apply.');
  });
});

describe('aka update — a managed install', () => {
  it('applies nothing for it, and does not call the machine current', async () => {
    seams.report = { statuses: [cliRow(), managedRow()], availablePlugins: [] };

    const { out, code } = await update(['--yes']);

    expect(code).toBe(0);
    expect(seams.pluginApplied).toEqual([]);
    expect(seams.cliApplied).toBe(0);
    expect(out).toContain('Managed by your organization:');
    expect(out).not.toContain('Will update:');
    expect(out).not.toContain('Everything is up to date');
    expect(out).toContain('Nothing for `aka update` to apply');
  });

  it('updates the CLI beside it and leaves the managed plugin alone', async () => {
    seams.report = {
      statuses: [cliRow({ latest: '0.9.14', updateAvailable: true }), managedRow()],
      availablePlugins: [],
    };

    const { out, code } = await update(['--yes']);

    expect(code).toBe(0);
    expect(seams.cliApplied).toBe(1);
    expect(seams.pluginApplied).toEqual([]);
    const bullets = out.split('\n').filter((line) => line.trimStart().startsWith('•'));
    expect(bullets).toHaveLength(1);
    expect(bullets[0]).toContain('aka CLI');
  });

  it('refuses an explicit `aka update claude-code`, naming the route that applies', async () => {
    seams.report = { statuses: [cliRow(), managedRow()], availablePlugins: [] };

    const { err, code } = await update(['--yes', 'claude-code']);

    expect(code).toBe(1);
    expect(seams.pluginApplied).toEqual([]);
    expect(err).toContain(managedUpdateRefusal('Claude Code'));
  });

  it('refuses an explicit target even once the host has caught up', async () => {
    // Not "already up to date": the answer that matters is that this command
    // is not the one that moves it, whatever its version.
    seams.report = {
      statuses: [cliRow(), managedRow({ installed: '0.9.14', managedInstall: { pending: false } })],
      availablePlugins: [],
    };

    const { err, code } = await update(['--yes', 'claude-code']);

    expect(code).toBe(1);
    expect(err).toContain(managedUpdateRefusal('Claude Code'));
  });

  it('still updates a plugin nobody manages (positive control)', async () => {
    // The same row without `managedInstall`, behind npm: it is offered and
    // applied, so the refusals above come from the managed marker alone.
    seams.report = {
      statuses: [
        cliRow(),
        {
          id: 'claude-code',
          name: 'Claude Code',
          kind: 'plugin',
          installed: '0.9.13',
          latest: '0.9.14',
          updateAvailable: true,
        },
      ],
      availablePlugins: [],
    };

    const { code } = await update(['--yes', 'claude-code']);

    expect(code).toBe(0);
    expect(seams.pluginApplied).toEqual(['claude-code']);
  });
});

/**
 * The ledger can gain a managed record between the report and the apply loop:
 * an organization's drop-in landing mid-run, or a report read from a stale
 * state. The row then still says "update available", so the CLI must check
 * again itself — the shared apply refuses, but in inherit mode its refusal is
 * returned rather than streamed, and the CLI had already announced commands
 * that were never going to run.
 */
describe('aka update — a plugin that became managed after the report', () => {
  const behindRow: ComponentStatus = {
    id: 'claude-code',
    name: 'Claude Code',
    kind: 'plugin',
    installed: '0.9.13',
    latest: '0.9.14',
    updateAvailable: true,
  };

  it('refuses before announcing a plan it will not run', async () => {
    seams.report = { statuses: [cliRow(), behindRow], availablePlugins: [] };
    seams.managed = { version: '0.9.13' };

    const { out, err, code } = await update(['--yes']);

    expect(code).toBe(1);
    expect(seams.pluginApplied).toEqual([]);
    expect(out).not.toContain('Updating Claude Code, running:');
    expect(err).toContain(managedUpdateRefusal('Claude Code'));
  });

  it('prints a refusal the shared apply returns instead of discarding it', async () => {
    // The narrower window: managed after the CLI's own check, so the shared
    // apply is the one that refuses. Its sentence is the only explanation.
    seams.report = { statuses: [cliRow(), behindRow], availablePlugins: [] };
    seams.pluginResult = { ok: false, output: managedUpdateRefusal('Claude Code') };

    const { err, code } = await update(['--yes']);

    expect(code).toBe(1);
    expect(seams.pluginApplied).toEqual(['claude-code']);
    expect(err).toContain(managedUpdateRefusal('Claude Code'));
  });
});

describe('aka update --channel — a managed plugin target', () => {
  it('says the organization decides, and hands out no marketplace recipe', async () => {
    // The recipe starts with `marketplace add <source>` and no ref: typed by
    // hand on a host that accepts it, that line is what replaces the
    // organization's pinned registration with an unpinned one.
    seams.managed = { version: '0.9.13', ref: 'fleet-v8' };

    const { err, code } = await update(['--yes', '--channel=beta', 'claude-code']);

    expect(code).toBe(1);
    expect(err).toContain('managed by your organization');
    expect(err).toContain(MANAGED_PLUGIN_ADVICE);
    expect(err).not.toContain('marketplace add');
    expect(seams.pluginApplied).toEqual([]);
  });

  it('keeps the recipe for a plugin nobody manages (positive control)', async () => {
    seams.managed = null;

    const { err, code } = await update(['--yes', '--channel=beta', 'claude-code']);

    expect(code).toBe(1);
    expect(err).toContain('marketplace add');
    expect(err).not.toContain('managed by your organization');
  });
});
