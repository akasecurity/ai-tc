import { describe, expect, it } from 'vitest';

import { gatherReport } from './updates.ts';

// A viewVersion stub keyed by package name.
function views(map: Record<string, string | null>): (pkg: string) => string | null {
  return (pkg) => map[pkg] ?? null;
}

const CLI = '@akasecurity/cli';
const PLUGIN = '@akasecurity/ai-tc-claude-code';
const REF = 'ai-tc@akasecurity';

describe('gatherReport', () => {
  it('flags a CLI update when the registry is ahead of the installed version', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.3', [PLUGIN]: '0.0.2-alpha.0' }),
      installed: new Map([[REF, '0.0.2-alpha.0']]),
      cliInstalled: '0.0.2-alpha.0',
    });
    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.updateAvailable).toBe(true);
    expect(cli?.latest).toBe('0.0.3');
  });

  it('reports an installed plugin as a status, not an available one', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.2', [PLUGIN]: '0.0.3' }),
      installed: new Map([[REF, '0.0.2']]),
      cliInstalled: '0.0.2',
    });
    expect(report.availablePlugins).toHaveLength(0);
    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.installed).toBe('0.0.2');
    expect(plugin?.updateAvailable).toBe(true);
  });

  it('surfaces an available plugin the user has not installed', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.2', [PLUGIN]: '0.0.3' }),
      installed: new Map(), // nothing installed
      cliInstalled: '0.0.2',
    });
    expect(report.statuses.map((s) => s.id)).toEqual(['cli']);
    expect(report.availablePlugins).toEqual([
      { id: 'claude-code', name: 'Claude Code', latest: '0.0.3' },
    ]);
  });

  it('never flags a CLI update when the installed version is unknown', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '9.9.9', [PLUGIN]: '0.0.1' }),
      installed: new Map([[REF, '0.0.1']]),
      cliInstalled: null, // package.json walk-up missed
    });
    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.installed).toBeNull();
    expect(cli?.updateAvailable).toBe(false);
  });

  it('never flags an update when the latest version is unknown (offline)', () => {
    const report = gatherReport({
      viewVersion: views({}), // every lookup returns null
      installed: new Map([[REF, '0.0.1']]),
      cliInstalled: '0.0.1',
    });
    for (const s of report.statuses) {
      expect(s.latest).toBeNull();
      expect(s.updateAvailable).toBe(false);
    }
  });
});
