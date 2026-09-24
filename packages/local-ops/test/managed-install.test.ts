// Whether an organization's managed settings installed a plugin.
//
// Claude Code records a plugin that a managed-settings drop-in force-enables
// at scope `managed`, and the version such an install runs is the one the
// organization's marketplace declaration pins — not npm's latest, and not
// something `aka update` may move. The comparison reader
// (`installedPluginVersions`) prefers a `user` record and falls back to any
// other, so it cannot answer this on its own: it has no way to say that the
// record it read belongs to somebody else.
//
// Driven against a real ledger and a real `known_marketplaces.json`, in the
// shapes read off a managed install, because the selection and the projection
// are one walk and a stub would pin the projection against a shape nothing
// proves the reader produces.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { findAgent } from '../src/registry.ts';
import { installedPluginVersions, managedPluginInstall } from '../src/updates.ts';

const REF = 'ai-tc@akasecurity';

function agentOf(id: string) {
  const agent = findAgent(id);
  if (agent === undefined) throw new Error(`the registry no longer carries ${id}`);
  return agent;
}

const claudeCode = agentOf('claude-code');

let claudeHome: string;

beforeEach(() => {
  claudeHome = mkdtempSync(join(tmpdir(), 'aka-managed-install-'));
});

afterEach(() => {
  rmSync(claudeHome, { recursive: true, force: true });
});

function writeLedger(plugins: Record<string, unknown>): void {
  const dir = join(claudeHome, 'plugins');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins }),
    'utf8',
  );
}

function writeKnownMarketplaces(known: Record<string, unknown>): void {
  const dir = join(claudeHome, 'plugins');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'known_marketplaces.json'), JSON.stringify(known), 'utf8');
}

/** The host's record of a marketplace an organization declared at a pinned ref. */
function pinnedMarketplace(ref: unknown): Record<string, unknown> {
  return {
    akasecurity: {
      source: { source: 'github', repo: 'akasecurity/marketplace', ref },
      installLocation: join(claudeHome, 'plugins', 'marketplaces', 'akasecurity'),
      autoUpdate: true,
    },
  };
}

describe('managedPluginInstall', () => {
  it('reports the version of a managed-scope record', () => {
    writeLedger({ [REF]: [{ scope: 'managed', version: '0.9.13' }] });

    expect(managedPluginInstall(claudeCode, claudeHome)).toEqual({ version: '0.9.13' });
  });

  it('says nothing for a user-scope install, which is the user’s own to update', () => {
    writeLedger({ [REF]: [{ scope: 'user', version: '0.9.13' }] });

    expect(managedPluginInstall(claudeCode, claudeHome)).toBeNull();
    // The positive control on the same ledger: the comparison reader still
    // sees the install, so the null above is about the scope, not a missed read.
    expect(installedPluginVersions(claudeHome).get(REF)).toBe('0.9.13');
  });

  it.each([
    [
      'managed first',
      [
        { scope: 'managed', version: '0.9.13' },
        { scope: 'user', version: '0.9.14' },
      ],
    ],
    [
      'user first',
      [
        { scope: 'user', version: '0.9.14' },
        { scope: 'managed', version: '0.9.13' },
      ],
    ],
  ])('reports the managed record when a user copy sits beside it (%s)', (_label, records) => {
    // The host resolves the managed copy when both exist — `claude plugin
    // details` reports the managed record's version — so that is the install
    // this machine runs, whichever order the ledger lists them in.
    writeLedger({ [REF]: records });

    expect(managedPluginInstall(claudeCode, claudeHome)).toEqual({ version: '0.9.13' });
    // The comparison reader is deliberately left as it was: it still prefers
    // the user record, which is what every non-managed install relies on.
    expect(installedPluginVersions(claudeHome).get(REF)).toBe('0.9.14');
  });

  it('carries the ref the host resolved the organization’s marketplace at', () => {
    writeLedger({ [REF]: [{ scope: 'managed', version: '0.9.13' }] });
    writeKnownMarketplaces(pinnedMarketplace('fleet-v8'));

    expect(managedPluginInstall(claudeCode, claudeHome)).toEqual({
      version: '0.9.13',
      ref: 'fleet-v8',
    });
  });

  it.each([
    ['no ref at all', undefined],
    ['an empty ref', ''],
    ['a non-string ref', 8],
    // Third-party text headed for a terminal: an escape sequence here could
    // repaint the line that is telling the user who manages this install.
    ['a ref carrying a control character', `fleet-v8${String.fromCharCode(27)}[2K`],
  ])('carries no ref for %s', (_label, ref) => {
    writeLedger({ [REF]: [{ scope: 'managed', version: '0.9.13' }] });
    writeKnownMarketplaces(pinnedMarketplace(ref));

    const lookup = managedPluginInstall(claudeCode, claudeHome);
    // The install is still managed — only the evidence is dropped.
    expect(lookup).toEqual({ version: '0.9.13' });
    expect(lookup).not.toHaveProperty('ref');
  });

  it('ignores a managed record carrying no version', () => {
    writeLedger({ [REF]: [{ scope: 'managed' }] });

    expect(managedPluginInstall(claudeCode, claudeHome)).toBeNull();
  });

  it.each([
    [
      'no ledger at all',
      (): void => {
        /* the temp home is created empty */
      },
    ],
    [
      'a ledger that is not JSON',
      (): void => {
        mkdirSync(join(claudeHome, 'plugins'), { recursive: true });
        writeFileSync(join(claudeHome, 'plugins', 'installed_plugins.json'), '{', 'utf8');
      },
    ],
    [
      'a ref whose records are not a list',
      (): void => {
        writeLedger({ [REF]: { scope: 'managed', version: '0.9.13' } });
      },
    ],
  ])('says nothing on %s rather than throwing', (_label, seed) => {
    seed();

    expect(managedPluginInstall(claudeCode, claudeHome)).toBeNull();
  });

  it('reads only Claude Code’s ledger for a Claude Code agent', () => {
    // Every other registered agent is hosted elsewhere, so a `managed` record
    // under its ref in THIS ledger says nothing about how it was installed —
    // the same host check the marketplace-pin reader makes.
    const codex = agentOf('codex');
    const antigravity = agentOf('antigravity');
    writeLedger({
      'aka-codex@ai-tc': [{ scope: 'managed', version: '0.9.13' }],
      [REF]: [{ scope: 'managed', version: '0.9.13' }],
    });

    expect(managedPluginInstall(codex, claudeHome)).toBeNull();
    expect(managedPluginInstall(antigravity, claudeHome)).toBeNull();
    // The control: the same ledger does answer for the agent it belongs to.
    expect(managedPluginInstall(claudeCode, claudeHome)).toEqual({ version: '0.9.13' });
  });
});
