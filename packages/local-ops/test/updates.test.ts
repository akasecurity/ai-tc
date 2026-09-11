import { describe, expect, it } from 'vitest';

import { gatherReport } from '../src/updates.ts';

// A viewVersion stub keyed by package name.
function views(map: Record<string, string | null>): (pkg: string) => string | null {
  return (pkg) => map[pkg] ?? null;
}

const CLI = '@akasecurity/cli';
const PLUGIN = '@akasecurity/ai-tc-claude-code';
const CODEX_PLUGIN = '@akasecurity/ai-tc-codex';
const REF = 'ai-tc@akasecurity';

describe('gatherReport', () => {
  it('flags a CLI update when the registry is ahead of the installed version', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.3', [PLUGIN]: '0.0.2-alpha.0' }),
      installed: new Map([[REF, '0.0.2-alpha.0']]),
      cliInstalled: '0.0.2-alpha.0',
      marketplacePin: () => null,
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
      marketplacePin: () => null,
    });
    // Codex CLI is a separate, uninstalled registry entry (a distinct ref —
    // see registry.ts's pluginName comment) so it still surfaces as available;
    // only claude-code, which IS in `installed`, must be excluded.
    expect(report.availablePlugins.map((p) => p.id)).toEqual(['codex']);
    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.installed).toBe('0.0.2');
    expect(plugin?.updateAvailable).toBe(true);
  });

  it('surfaces an available plugin the user has not installed', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.2', [PLUGIN]: '0.0.3', [CODEX_PLUGIN]: '0.1.0' }),
      installed: new Map(), // nothing installed
      cliInstalled: '0.0.2',
      marketplacePin: () => null,
    });
    expect(report.statuses.map((s) => s.id)).toEqual(['cli']);
    // Every registered agent with no installed version surfaces here — both
    // Claude Code and Codex CLI (see registry.ts's AGENT_PLUGINS).
    expect(report.availablePlugins).toEqual([
      { id: 'claude-code', name: 'Claude Code', latest: '0.0.3' },
      { id: 'codex', name: 'Codex CLI', latest: '0.1.0' },
    ]);
  });

  it('never flags a CLI update when the installed version is unknown', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '9.9.9', [PLUGIN]: '0.0.1' }),
      installed: new Map([[REF, '0.0.1']]),
      cliInstalled: null, // package.json walk-up missed
      marketplacePin: () => null,
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
      marketplacePin: () => null,
    });
    for (const s of report.statuses) {
      expect(s.latest).toBeNull();
      expect(s.updateAvailable).toBe(false);
    }
  });
});

// The pin WINS over npm, because it is what the host resolves an install
// through. Reading "latest" off npm let the report offer an update
// `claude plugin update` structurally could not deliver: a consent prompt
// promising a state change that cannot happen, and — under a marketplace
// registered at a pinned ref — the same one on every run, no-opping each time.
//
// The two agree on the happy path, which is why this was latent rather than
// obvious. Every case below is a state where they come apart.
describe('gatherReport — the marketplace pin decides what "latest" means', () => {
  const pinned = (version: string | null) => (): string | null => version;

  it('reports the PIN as latest, not npm', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.9.9');
    expect(plugin?.marketplacePin).toEqual({
      marketplace: 'akasecurity',
      npmLatest: '0.9.10',
      // npm is ahead of the pin, which is the only case worth explaining.
      npmAhead: true,
    });
  });

  it('does NOT offer an update the host cannot install', () => {
    // The defect, stated as the case it produced: npm is ahead, the manifest is
    // not, and the installed version already equals the pin. Before this, the
    // row said "update available" and the apply resolved back to what was
    // already there.
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.9']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
    });

    expect(report.statuses.find((s) => s.id === 'claude-code')?.updateAvailable).toBe(false);
  });

  it('still offers an update the host CAN install', () => {
    // The positive control for the case above: pinning must not be a way to
    // stop reporting updates. A pin ahead of the installed version is a real
    // update and the host will deliver it.
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
    });

    expect(report.statuses.find((s) => s.id === 'claude-code')?.updateAvailable).toBe(true);
  });

  it('falls back to npm when no pin applies, which is what shipped', () => {
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned(null),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.9.10');
    expect(plugin?.updateAvailable).toBe(true);
    // Absent rather than null: a surface spreading the status carries no key,
    // and "npm answered" is not a pin worth rendering.
    expect(plugin).not.toHaveProperty('marketplacePin');
  });

  it('carries the pin onto a plugin that is not installed yet', () => {
    // `availablePlugins` is what `aka plugins install` would deliver, so it has
    // to name the same version the install will actually reach.
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map(),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
    });

    expect(report.availablePlugins.find((p) => p.id === 'claude-code')?.latest).toBe('0.9.9');
  });

  it('leaves the CLI alone, which npm really is the install path for', () => {
    // The CLI is not a marketplace plugin. A pin reaching its row would be this
    // defect inverted — reporting a ceiling that does not apply to it.
    const report = gatherReport({
      viewVersion: views({ [CLI]: '9.9.9', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.9']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
    });

    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.latest).toBe('9.9.9');
    expect(cli?.updateAvailable).toBe(true);
    expect(cli).not.toHaveProperty('marketplacePin');
  });

  it('keeps npm unread-from but still ASKED, so the note can explain itself', () => {
    // The npm answer is kept beside the pin rather than dropped: it is the only
    // thing that can explain a row reading "up to date" at a version the user
    // can see is behind. A report that silently used the pin and forgot npm
    // would be correct and unreadable.
    const report = gatherReport({
      viewVersion: views({ [CLI]: '0.0.1', [PLUGIN]: null }),
      installed: new Map([[REF, '0.9.9']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
    });

    expect(report.statuses.find((s) => s.id === 'claude-code')?.marketplacePin).toEqual({
      marketplace: 'akasecurity',
      npmLatest: null,
      // Nothing to compare against, so nothing to explain.
      npmAhead: false,
    });
  });
});
