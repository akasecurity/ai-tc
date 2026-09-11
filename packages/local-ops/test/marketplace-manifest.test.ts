// What the HOST will install, as opposed to what npm has published.
//
// `aka update` asked npm; `claude plugin install` / `plugin update` resolve
// through the marketplace manifest, whose entries name an exact version.
// Nothing reconciled the two, so the report could offer an update the host
// structurally cannot deliver — and under a marketplace registered at a pinned
// ref, offer the same one on every run and no-op every time.
//
// Driven against a real on-disk layout rather than a stub, because the shape is
// the host's and not ours: these fixtures are the shapes read off a working
// install (`known_marketplaces.json` carrying `installLocation`, and a
// `marketplace.json` whose npm entries carry `source.version` while its github
// and git-subdir entries carry none).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { marketplacePinnedVersion } from '../src/marketplace-manifest.ts';
import type { AgentPlugin } from '../src/registry.ts';

/** A Claude-Code-hosted agent with the coordinates a lookup needs. */
const agent = (over: Partial<AgentPlugin> = {}): AgentPlugin => ({
  id: 'claude-code',
  name: 'Claude Code plugin',
  sourceTool: 'claude-code',
  description: '',
  npmPackage: '@akasecurity/ai-tc-claude-code',
  pluginName: 'ai-tc',
  marketplace: 'akasecurity',
  cliBin: 'claude',
  ...over,
});

let claudeHome: string;

beforeEach(() => {
  claudeHome = mkdtempSync(join(tmpdir(), 'aka-marketplace-'));
});

afterEach(() => {
  rmSync(claudeHome, { recursive: true, force: true });
});

/** Register a marketplace the way the host does, and write its manifest. */
function registerMarketplace(name: string, plugins: unknown[]): string {
  const root = join(claudeHome, 'plugins', 'marketplaces', name);
  mkdirSync(join(root, '.claude-plugin'), { recursive: true });
  writeFileSync(
    join(root, '.claude-plugin', 'marketplace.json'),
    JSON.stringify({ name, owner: {}, metadata: {}, plugins }),
    'utf8',
  );
  const knownPath = join(claudeHome, 'plugins', 'known_marketplaces.json');
  writeFileSync(
    knownPath,
    JSON.stringify({
      [name]: { source: { source: 'github', repo: `x/${name}` }, installLocation: root },
    }),
    'utf8',
  );
  return root;
}

const npmEntry = (name: string, version: string): unknown => ({
  name,
  source: { source: 'npm', package: `@akasecurity/${name}`, version },
});

describe('marketplacePinnedVersion', () => {
  it('reads the version the host would install', () => {
    registerMarketplace('akasecurity', [npmEntry('ai-tc', '0.9.9')]);

    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'akasecurity', pluginName: 'ai-tc' }),
        claudeHome,
      ),
    ).toBe('0.9.9');
  });

  it('picks the named plugin out of a manifest listing several', () => {
    // The real manifest lists every plugin the marketplace offers, so matching
    // by name rather than taking the first entry is the whole read.
    registerMarketplace('akasecurity', [
      { name: 'preflight', source: { source: 'github', repo: 'x/preflight' } },
      npmEntry('ai-tc', '0.9.9'),
      npmEntry('other', '1.2.3'),
    ]);

    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'akasecurity', pluginName: 'ai-tc' }),
        claudeHome,
      ),
    ).toBe('0.9.9');
    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'akasecurity', pluginName: 'other' }),
        claudeHome,
      ),
    ).toBe('1.2.3');
  });

  it('says nothing for an entry that carries no pin', () => {
    // A `github` / `git-subdir` source has no version, and for those the host
    // really does follow the published head — so npm's latest is the right
    // answer and the caller must fall back to it rather than reporting "no
    // update available".
    registerMarketplace('akasecurity', [
      { name: 'preflight', source: { source: 'github', repo: 'akasecurity/preflight-skills' } },
    ]);

    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'akasecurity', pluginName: 'preflight' }),
        claudeHome,
      ),
    ).toBeNull();
  });

  it('follows installLocation rather than assuming the conventional layout', () => {
    // The host states where it put the marketplace. A reader that assembled
    // `<home>/plugins/marketplaces/<name>` would answer confidently for a host
    // that moved it — and be wrong, which is worse than saying nothing.
    const elsewhere = join(claudeHome, 'somewhere-else');
    mkdirSync(join(elsewhere, '.claude-plugin'), { recursive: true });
    writeFileSync(
      join(elsewhere, '.claude-plugin', 'marketplace.json'),
      JSON.stringify({ plugins: [npmEntry('ai-tc', '1.1.1')] }),
      'utf8',
    );
    mkdirSync(join(claudeHome, 'plugins'), { recursive: true });
    writeFileSync(
      join(claudeHome, 'plugins', 'known_marketplaces.json'),
      JSON.stringify({ akasecurity: { installLocation: elsewhere } }),
      'utf8',
    );

    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'akasecurity', pluginName: 'ai-tc' }),
        claudeHome,
      ),
    ).toBe('1.1.1');
  });

  it.each([
    [
      'nothing registered',
      (): void => {
        /* the temp home is created empty */
      },
    ],
    [
      'a marketplace registered with no installLocation',
      (): void => {
        mkdirSync(join(claudeHome, 'plugins'), { recursive: true });
        writeFileSync(
          join(claudeHome, 'plugins', 'known_marketplaces.json'),
          JSON.stringify({ akasecurity: { source: {} } }),
          'utf8',
        );
      },
    ],
    [
      'a registered marketplace whose manifest is missing',
      (): void => {
        mkdirSync(join(claudeHome, 'plugins'), { recursive: true });
        writeFileSync(
          join(claudeHome, 'plugins', 'known_marketplaces.json'),
          JSON.stringify({ akasecurity: { installLocation: join(claudeHome, 'gone') } }),
          'utf8',
        );
      },
    ],
    [
      'a damaged known_marketplaces.json',
      (): void => {
        mkdirSync(join(claudeHome, 'plugins'), { recursive: true });
        writeFileSync(join(claudeHome, 'plugins', 'known_marketplaces.json'), '{ not json', 'utf8');
      },
    ],
    [
      'a damaged manifest',
      (): void => {
        const root = registerMarketplace('akasecurity', []);
        writeFileSync(join(root, '.claude-plugin', 'marketplace.json'), '{ not json', 'utf8');
      },
    ],
    [
      'a plugin the manifest does not list',
      (): void => {
        registerMarketplace('akasecurity', [npmEntry('something-else', '2.0.0')]);
      },
    ],
    [
      'an entry whose version is empty',
      (): void => {
        registerMarketplace('akasecurity', [
          { name: 'ai-tc', source: { source: 'npm', package: 'x', version: '' } },
        ]);
      },
    ],
  ])('says nothing on %s, rather than throwing', (_label, seed) => {
    // Every one of these is "no ANSWER", and the caller falls back to npm — the
    // behaviour that shipped. Failing open matters more here than being clever:
    // a throw would take down `aka update` and the passive notice with it.
    seed();

    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'akasecurity', pluginName: 'ai-tc' }),
        claudeHome,
      ),
    ).toBeNull();
  });

  it('answers nothing for a Codex-hosted agent, whatever its coordinates say', () => {
    // The registry's Codex entry carries `marketplace: 'ai-tc'` and
    // `pluginName: 'aka-codex'` like any other, so a caller gating on "are the
    // coordinates present" admits it into a reader that only understands Claude
    // Code's layout — answering it out of `~/.claude`'s ledger. Inert today only
    // because no marketplace named `ai-tc` is registered there, which is one
    // `plugin marketplace add` away from being false.
    registerMarketplace('ai-tc', [npmEntry('aka-codex', '9.9.9')]);

    expect(
      marketplacePinnedVersion(
        agent({ cliBin: 'codex', marketplace: 'ai-tc', pluginName: 'aka-codex' }),
        claudeHome,
      ),
    ).toBeNull();
    // The control on the line above: that manifest IS readable, so the null is
    // the host check rather than a lookup that failed for its own reasons.
    expect(
      marketplacePinnedVersion(
        agent({ cliBin: 'claude', marketplace: 'ai-tc', pluginName: 'aka-codex' }),
        claudeHome,
      ),
    ).toBe('9.9.9');
  });

  it.each<'marketplace' | 'pluginName'>(['marketplace', 'pluginName'])(
    'answers nothing for an agent carrying no %s',
    (field) => {
      // `exactOptionalPropertyTypes` makes an explicit `undefined` a different
      // thing from an absent key, and the registry's own entries omit these
      // rather than setting them undefined — so the fixture deletes the key.
      registerMarketplace('akasecurity', [npmEntry('ai-tc', '0.9.9')]);
      // Rebuilt WITHOUT the key rather than deleted from a complete one:
      // `exactOptionalPropertyTypes` makes an explicit `undefined` a different
      // thing from an absent key, and the registry's entries omit these.
      const incomplete = Object.fromEntries(
        Object.entries(agent()).filter(([key]) => key !== field),
      ) as AgentPlugin;

      expect(marketplacePinnedVersion(incomplete, claudeHome)).toBeNull();
    },
  );

  it('does not confuse two marketplaces that list the same plugin name', () => {
    // The control on the lookup: registering one marketplace must not make its
    // pin answer for another's, which a reader keyed only on plugin name would.
    registerMarketplace('akasecurity', [npmEntry('ai-tc', '0.9.9')]);

    expect(
      marketplacePinnedVersion(
        agent({ marketplace: 'some-other-marketplace', pluginName: 'ai-tc' }),
        claudeHome,
      ),
    ).toBeNull();
  });
});
