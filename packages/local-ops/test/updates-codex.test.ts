// Tests installedCodexPluginVersions() / installedAgentPluginVersions()
// against a synthetic `~/.codex/plugins/cache/<marketplace>/<plugin>/<version>/`
// layout — the directory-walk counterpart to installedPluginVersions()'s
// single-file ledger read. The "active version" selection rule (highest
// semver, `local` always wins) is confirmed against openai/codex's own
// `PluginStore::active_plugin_version` (codex-rs/core-plugins/src/store.rs).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { installedAgentPluginVersions, installedCodexPluginVersions } from '../src/updates.ts';

let codexHome: string;

beforeEach(() => {
  codexHome = mkdtempSync(join(tmpdir(), 'aka-codex-home-'));
});

afterEach(() => {
  rmSync(codexHome, { recursive: true, force: true });
});

function makeCacheDir(marketplace: string, plugin: string, ...versions: string[]): void {
  for (const version of versions) {
    mkdirSync(join(codexHome, 'plugins', 'cache', marketplace, plugin, version), {
      recursive: true,
    });
  }
}

describe('installedCodexPluginVersions', () => {
  it('returns empty when the cache root does not exist', () => {
    expect(installedCodexPluginVersions(codexHome)).toEqual(new Map());
  });

  it('resolves the single installed version for the codex agent', () => {
    makeCacheDir('ai-tc', 'aka-codex', '0.1.0');
    expect(installedCodexPluginVersions(codexHome)).toEqual(
      new Map([['aka-codex@ai-tc', '0.1.0']]),
    );
  });

  it('picks the highest semver when multiple version dirs are present', () => {
    makeCacheDir('ai-tc', 'aka-codex', '0.1.0', '0.2.0', '0.1.5');
    expect(installedCodexPluginVersions(codexHome)).toEqual(
      new Map([['aka-codex@ai-tc', '0.2.0']]),
    );
  });

  it('a literal "local" version directory always wins (dev-mode install marker)', () => {
    makeCacheDir('ai-tc', 'aka-codex', '0.1.0', '0.2.0', 'local');
    expect(installedCodexPluginVersions(codexHome)).toEqual(
      new Map([['aka-codex@ai-tc', 'local']]),
    );
  });

  it('ignores non-directory entries under the plugin cache dir', () => {
    makeCacheDir('ai-tc', 'aka-codex', '0.1.0');
    // A stray file (e.g. a lockfile) alongside the version directories must
    // never be treated as a version.
    writeFileSync(join(codexHome, 'plugins', 'cache', 'ai-tc', 'aka-codex', 'installed.lock'), '');
    expect(installedCodexPluginVersions(codexHome)).toEqual(
      new Map([['aka-codex@ai-tc', '0.1.0']]),
    );
  });
});

describe('installedAgentPluginVersions', () => {
  it('merges the Codex cache read with the (missing) Claude Code ledger without colliding', () => {
    makeCacheDir('ai-tc', 'aka-codex', '0.3.0');
    // A nonexistent claudeHome — the Claude side contributes nothing, but must
    // not clobber or omit the Codex entry.
    const merged = installedAgentPluginVersions(join(codexHome, 'no-such-claude-home'), codexHome);
    expect(merged.get('aka-codex@ai-tc')).toBe('0.3.0');
    expect(merged.size).toBe(1);
  });
});
