import type { DistTags, ReleaseChannel, ReleaseTagSource } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL, RELEASE_TAG_SOURCE } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { MarketplacePinLookup } from '../src/marketplace-manifest.ts';
import { AGENT_PLUGINS, pluginRef } from '../src/registry.ts';
import { resolveChannel } from '../src/release-channel.ts';
import { gatherReport } from '../src/updates.ts';

// A viewDistTags stub keyed by package name, serving each package's version on
// the `latest` tag alone — the registry a machine with no prerelease published
// sees, which is what every case predating channels means by a version.
function views(map: Record<string, string | null>): (pkg: string) => DistTags | null {
  return (pkg) => {
    const version = map[pkg] ?? null;
    return version === null ? null : { [DIST_TAG[RELEASE_CHANNEL.Stable]]: version };
  };
}

// A stub serving a whole tag map per package, for the cases whose subject is
// which tag gets read.
function tagged(map: Record<string, DistTags>): (pkg: string) => DistTags | null {
  return (pkg) => map[pkg] ?? null;
}

const CLI = '@akasecurity/cli';
const PLUGIN = '@akasecurity/ai-tc-claude-code';
const CODEX_PLUGIN = '@akasecurity/ai-tc-codex';
const REF = 'ai-tc@akasecurity';

describe('gatherReport', () => {
  it('flags a CLI update when the registry is ahead of the installed version', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.3', [PLUGIN]: '0.0.2-alpha.0' }),
      installed: new Map([[REF, '0.0.2-alpha.0']]),
      cliInstalled: '0.0.2-alpha.0',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });
    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.updateAvailable).toBe(true);
    expect(cli?.latest).toBe('0.0.3');
  });

  it('reports an installed plugin as a status, not an available one', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.2', [PLUGIN]: '0.0.3' }),
      installed: new Map([[REF, '0.0.2']]),
      cliInstalled: '0.0.2',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
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
      viewDistTags: views({ [CLI]: '0.0.2', [PLUGIN]: '0.0.3', [CODEX_PLUGIN]: '0.1.0' }),
      installed: new Map(), // nothing installed
      cliInstalled: '0.0.2',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
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
      viewDistTags: views({ [CLI]: '9.9.9', [PLUGIN]: '0.0.1' }),
      installed: new Map([[REF, '0.0.1']]),
      cliInstalled: null, // package.json walk-up missed
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });
    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.installed).toBeNull();
    expect(cli?.updateAvailable).toBe(false);
  });

  it('never flags an update when the latest version is unknown (offline)', () => {
    const report = gatherReport({
      viewDistTags: views({}), // every lookup returns null
      installed: new Map([[REF, '0.0.1']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
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
  const pinned = (version: string | null) => (): MarketplacePinLookup => ({ version });

  it('reports the PIN as latest, not npm', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
      managedInstall: () => null,
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
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.9']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
      managedInstall: () => null,
    });

    expect(report.statuses.find((s) => s.id === 'claude-code')?.updateAvailable).toBe(false);
  });

  it('still offers an update the host CAN install', () => {
    // The positive control for the case above: pinning must not be a way to
    // stop reporting updates. A pin ahead of the installed version is a real
    // update and the host will deliver it.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
      managedInstall: () => null,
    });

    expect(report.statuses.find((s) => s.id === 'claude-code')?.updateAvailable).toBe(true);
  });

  it('falls back to npm when no pin applies, which is what shipped', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned(null),
      managedInstall: () => null,
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
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map(),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
      managedInstall: () => null,
    });

    expect(report.availablePlugins.find((p) => p.id === 'claude-code')?.latest).toBe('0.9.9');
  });

  it('leaves the CLI alone, which npm really is the install path for', () => {
    // The CLI is not a marketplace plugin. A pin reaching its row would be this
    // defect inverted — reporting a ceiling that does not apply to it.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '9.9.9', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.9']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
      managedInstall: () => null,
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
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: null }),
      installed: new Map([[REF, '0.9.9']]),
      cliInstalled: '0.0.1',
      marketplacePin: pinned('0.9.9'),
      managedInstall: () => null,
    });

    expect(report.statuses.find((s) => s.id === 'claude-code')?.marketplacePin).toEqual({
      marketplace: 'akasecurity',
      npmLatest: null,
      // Nothing to compare against, so nothing to explain.
      npmAhead: false,
    });
  });
});

// A RANGE pin (or a dist-tag) is not a version this report can compare, so it
// must not be reported as npm's own latest was before it — a bounded range
// that excludes npm's answer would otherwise offer an update the host can
// never resolve to, and re-nag on every run once the host installed within
// the range instead. This is `gatherReport`'s own wiring of
// `marketplacePinnedVersion`'s `range` evidence, not a re-test of that
// function in isolation.
describe("gatherReport — a RANGE pin must not offer npm's answer as an update", () => {
  const rangePinned = (range: string) => (): MarketplacePinLookup => ({ version: null, range });

  it("does NOT offer npm's latest when the manifest pins a range", () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.12.0' }),
      installed: new Map([[REF, '0.11.0-beta.0']]),
      cliInstalled: '0.0.1',
      marketplacePin: rangePinned('^0.11.0-beta.0'),
      managedInstall: () => null,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    // npm's answer is kept for the "Latest" column — informational, the pin's
    // own note is what explains it — but the row must not claim an update is
    // available for a version the host cannot resolve the range to.
    expect(plugin?.latest).toBe('0.12.0');
    expect(plugin?.updateAvailable).toBe(false);
    expect(plugin?.marketplacePin).toEqual({
      marketplace: 'akasecurity',
      npmLatest: '0.12.0',
      npmAhead: false,
      range: '^0.11.0-beta.0',
    });
  });

  it('still offers the update with the SAME data and no pin (positive control)', () => {
    // Identical installed/npm data, only the pin removed: proves the refusal
    // above comes from the range rather than from anything else in the
    // fixture, so the case above cannot pass vacuously.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.12.0' }),
      installed: new Map([[REF, '0.11.0-beta.0']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.12.0');
    expect(plugin?.updateAvailable).toBe(true);
  });
});

// The channel a component follows is DERIVED from the version that component is
// running, per component, every time the report is built. Nothing stores it, so
// there is no state here to go stale — but there is a whole class of defect that
// reads perfectly: resolving one channel for the whole report, or resolving it
// from the TAGS the registry happens to serve rather than from what is
// installed. Both typecheck, and both put a machine on a line it never chose.
describe('gatherReport — each row resolves its own channel', () => {
  const STABLE_AND_BETA: DistTags = { latest: '0.9.12', beta: '0.11.0-beta.3' };

  it('resolves the CLI and a plugin on DIFFERENT channels in one report', () => {
    const report = gatherReport({
      viewDistTags: tagged({ [CLI]: STABLE_AND_BETA, [PLUGIN]: STABLE_AND_BETA }),
      installed: new Map([[REF, '0.11.0-beta.2']]),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.channel).toBe(RELEASE_CHANNEL.Stable);
    expect(cli?.latest).toBe('0.9.12');
    expect(cli?.updateAvailable).toBe(true);

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.channel).toBe(RELEASE_CHANNEL.Beta);
    expect(plugin?.latest).toBe('0.11.0-beta.3');
    expect(plugin?.updateAvailable).toBe(true);
  });

  it('offers a stable install the stable tag and never a prerelease', () => {
    const report = gatherReport({
      viewDistTags: tagged({ [CLI]: STABLE_AND_BETA }),
      installed: new Map(),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    expect(report.statuses.find((s) => s.id === 'cli')?.latest).toBe('0.9.12');
  });

  it('graduates a beta install onto the stable of the same core', () => {
    // Why the resolution takes a MAX rather than the channel's own tag: `beta`
    // goes on pointing at the prerelease after the release ships, so a reader
    // taking that tag alone strands this machine on 0.11.0-beta.3 for ever with
    // the row reading "up to date".
    const report = gatherReport({
      viewDistTags: tagged({ [PLUGIN]: { latest: '0.11.0', beta: '0.11.0-beta.3' } }),
      installed: new Map([[REF, '0.11.0-beta.2']]),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.11.0');
    expect(plugin?.updateAvailable).toBe(true);
  });

  it('does not nag a beta install backwards to an older stable', () => {
    // No beta tag published yet, so the resolution falls back to `latest` —
    // which is BEHIND this install. The fallback must not become an offer.
    const report = gatherReport({
      viewDistTags: tagged({ [CLI]: { latest: '0.9.12' } }),
      installed: new Map(),
      cliInstalled: '0.11.0-beta.2',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.channel).toBe(RELEASE_CHANNEL.Beta);
    expect(cli?.latest).toBe('0.9.12');
    expect(cli?.updateAvailable).toBe(false);
  });

  it('follows the nightly tag for a nightly install', () => {
    const report = gatherReport({
      viewDistTags: tagged({
        [CLI]: { latest: '0.9.12', nightly: '0.9.13-nightly.20260919.gdef5678' },
      }),
      installed: new Map(),
      cliInstalled: '0.9.13-nightly.20260918.gabc1234',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.channel).toBe(RELEASE_CHANNEL.Nightly);
    expect(cli?.latest).toBe('0.9.13-nightly.20260919.gdef5678');
    expect(cli?.updateAvailable).toBe(true);
  });

  it('resolves a plugin nobody has installed on stable', () => {
    // A machine with nothing installed has opted into nothing, so the version
    // advertised under "available plugins" stays the stable one even while a
    // prerelease is published.
    const report = gatherReport({
      viewDistTags: tagged({ [PLUGIN]: STABLE_AND_BETA, [CODEX_PLUGIN]: STABLE_AND_BETA }),
      installed: new Map(),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    expect(report.availablePlugins.length).toBeGreaterThan(0);
    for (const available of report.availablePlugins) {
      expect(available.latest, available.id).toBe('0.9.12');
    }
  });

  it('falls a refused pin through to the channel-resolved answer', () => {
    // The composition that makes a non-exact marketplace pin usable rather than
    // freezing: the pin reader refuses it, and what the row then carries is the
    // version the channel resolution produced — not npm's stable, and not the
    // pin string.
    const report = gatherReport({
      viewDistTags: tagged({ [PLUGIN]: STABLE_AND_BETA }),
      installed: new Map([[REF, '0.11.0-beta.2']]),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.11.0-beta.3');
    expect(plugin).not.toHaveProperty('marketplacePin');
  });

  it('stays silent when the lookup produced no answer at all', () => {
    // The fail-open row, unchanged by channels: an unreadable registry answer
    // is `unknown`, never a nag and never a throw.
    const report = gatherReport({
      viewDistTags: () => null,
      installed: new Map([[REF, '0.11.0-beta.2']]),
      cliInstalled: '0.11.0-beta.2',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    expect(report.statuses.length).toBeGreaterThan(1);
    for (const s of report.statuses) {
      expect(s.latest, s.id).toBeNull();
      expect(s.updateAvailable, s.id).toBe(false);
    }
  });
});

// A caller switching the CLI onto another published line is asking about a
// channel this copy is NOT on, so the row cannot be resolved against the
// derived one. The consequence is not a cosmetic label: `updateAvailable` is
// what decides whether anything is applied, so a report resolved against the
// channel being left reports a current machine as having nothing to do — and
// the switch silently does not happen.
describe('gatherReport — an explicitly requested CLI channel', () => {
  const STABLE_AND_BETA: DistTags = { latest: '0.9.12', beta: '0.11.0-beta.3' };

  const cliRow = (deps: Partial<Parameters<typeof gatherReport>[0]>) =>
    gatherReport({
      viewDistTags: tagged({ [CLI]: STABLE_AND_BETA, [PLUGIN]: STABLE_AND_BETA }),
      installed: new Map([[REF, '0.9.11']]),
      cliInstalled: '0.9.12',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
      ...deps,
    }).statuses.find((s) => s.id === 'cli');

  it('offers a machine that is current on stable the requested channel instead', () => {
    // Without the override this row reads latest 0.9.12 against installed
    // 0.9.12 and `updateAvailable` false, so nothing is ever applied.
    const derived = cliRow({});
    expect(derived?.channel).toBe(RELEASE_CHANNEL.Stable);
    expect(derived?.updateAvailable).toBe(false);

    const asked = cliRow({ cliChannel: RELEASE_CHANNEL.Beta });
    expect(asked?.channel).toBe(RELEASE_CHANNEL.Beta);
    expect(asked?.latest).toBe('0.11.0-beta.3');
    expect(asked?.updateAvailable).toBe(true);
  });

  it('brings a prerelease machine back to the stable it is behind', () => {
    const asked = cliRow({
      cliInstalled: '0.11.0-beta.2',
      viewDistTags: tagged({ [CLI]: { latest: '0.11.0', beta: '0.11.0-beta.3' } }),
      cliChannel: RELEASE_CHANNEL.Stable,
    });

    expect(asked?.channel).toBe(RELEASE_CHANNEL.Stable);
    expect(asked?.latest).toBe('0.11.0');
    expect(asked?.updateAvailable).toBe(true);
  });

  it('leaves every plugin row on its own derived channel', () => {
    // The override is CLI-only: a plugin's channel is its marketplace
    // registration, which this process cannot change, so asking for one must
    // not relabel or re-resolve a plugin row.
    const report = gatherReport({
      viewDistTags: tagged({ [CLI]: STABLE_AND_BETA, [PLUGIN]: STABLE_AND_BETA }),
      installed: new Map([[REF, '0.9.11']]),
      cliInstalled: '0.9.12',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
      cliChannel: RELEASE_CHANNEL.Beta,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin).toBeDefined();
    expect(plugin?.channel).toBe(RELEASE_CHANNEL.Stable);
    expect(plugin?.latest).toBe('0.9.12');
  });

  it('reads as absent when it is undefined, not as stable', () => {
    // The optional field arrives `undefined` from a caller that has no flag to
    // pass on — `gatherReportLive(undefined)` — so the fallback has to be the
    // derivation rather than the first member of the union.
    const asked = cliRow({ cliInstalled: '0.11.0-beta.2', cliChannel: undefined });
    expect(asked?.channel).toBe(RELEASE_CHANNEL.Beta);
  });
});

// One registry request per package, which is what the egress disclosure counts.
// A recording seam is the only place this can be asserted here: the count
// crosses a package wall to reach cli/README.md's derived numeral, so a second
// read added on this path would otherwise be discovered over there rather than
// where it was written.
describe('gatherReport — exactly one registry read per package', () => {
  function record(answer: (pkg: string) => DistTags | null): {
    seam: (pkg: string) => DistTags | null;
    calls: string[];
  } {
    const calls: string[] = [];
    return {
      calls,
      seam: (pkg) => {
        calls.push(pkg);
        return answer(pkg);
      },
    };
  }

  /**
   * The packages a report must ask about, derived from the registry rather than
   * listed — the CLI plus every agent carrying BOTH a ref and an npm package.
   *
   * Asserting the call list against this EXACTLY is what makes the guard bite
   * on an unconditional second read as well as on a conditional one: a
   * `toBeGreaterThan` floor plus a no-duplicates check passes a second read
   * that happens to ask about something else, and a duplicate check alone
   * passes a fallback whose fixture never enters the failure branch.
   */
  const EXPECTED_LOOKUPS = [
    CLI,
    ...AGENT_PLUGINS.filter((agent) => pluginRef(agent) && agent.npmPackage).map(
      (agent) => agent.npmPackage,
    ),
  ];

  it('has more than one package to ask about', () => {
    // Without this the exact-match assertions below would hold over a
    // single-entry list and say almost nothing.
    expect(EXPECTED_LOOKUPS.length).toBeGreaterThan(1);
  });

  it('asks once per package, in order, with no repeats', () => {
    const { seam, calls } = record(() => ({ latest: '0.9.12', beta: '0.11.0-beta.3' }));
    gatherReport({
      viewDistTags: seam,
      installed: new Map([[REF, '0.11.0-beta.2']]),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    expect(calls).toStrictEqual(EXPECTED_LOOKUPS);
  });

  it('asks once per package even when EVERY answer is unusable', () => {
    // The failure branch of the read, driven rather than reasoned about — and
    // driven for every package, because a fixture that answers some of them
    // leaves the fallback path a second read would take unreachable, which is
    // how this case was inert when it was first written.
    const { seam, calls } = record(() => null);
    gatherReport({
      viewDistTags: seam,
      installed: new Map([[REF, '0.11.0-beta.2']]),
      cliInstalled: '0.11.0-beta.2',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    expect(calls).toStrictEqual(EXPECTED_LOOKUPS);
  });

  it('asks the same packages whether or not anything is installed', () => {
    // The disclosure says the plugin lookups run whether or not the plugin is
    // installed, so gating a read on the installed map would make that copy
    // false — and would leave the count word on the CLI's own README wrong.
    const empty = record(() => ({ latest: '0.9.12' }));
    gatherReport({
      viewDistTags: empty.seam,
      installed: new Map(),
      cliInstalled: null,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    expect(empty.calls).toStrictEqual(EXPECTED_LOOKUPS);
  });
});

// WHICH dist-tag a row's `latest` came from, carried onto the row itself.
//
// The field exists so a caller that asked for a channel BY NAME can refuse a
// line nothing publishes rather than offering it the stable version it would
// then fail to fetch. That refusal lives in the CLI, so this package's own
// suite is the only thing that can catch the field being dropped or mislabelled
// here — remove it from the CLI row and `@akasecurity/cli` reds while this
// package stays green, which is the wrong way round for the package that
// produces it.
describe('gatherReport — where a row’s `latest` was resolved from', () => {
  // Asserted against `resolveChannel` rather than against a literal source, so
  // a resolution that moved would move both and neither could be right alone.
  const sourceFor = (tags: DistTags | null, channel: ReleaseChannel): ReleaseTagSource =>
    resolveChannel(tags, channel).source;

  const registries: [string, DistTags | null, ReleaseChannel][] = [
    // The channel's own tag decided.
    ['a published channel', { latest: '0.9.12', beta: '0.11.0-beta.4' }, RELEASE_CHANNEL.Beta],
    // The stable overtook the prerelease — the graduation row.
    ['a graduated prerelease', { latest: '0.11.0', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta],
    // The channel serves no tag at all, so `latest` is the stable fallback.
    ['a channel nothing publishes', { latest: '0.9.12' }, RELEASE_CHANNEL.Nightly],
    // No tag map at all.
    ['an unreachable registry', null, RELEASE_CHANNEL.Beta],
  ];

  it.each(registries)('names the tag the CLI row came from — %s', (_name, tags, channel) => {
    const report = gatherReport({
      viewDistTags: (pkg) => (pkg === CLI ? tags : null),
      installed: new Map(),
      cliInstalled: '0.9.11',
      cliChannel: channel,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli).toBeDefined();
    expect(cli?.latestFrom).toBe(sourceFor(tags, channel));
    // And the version beside it is the same resolution's, so the pair cannot
    // describe two different answers.
    expect(cli?.latest).toBe(resolveChannel(tags, channel).version);
  });

  it('distinguishes the four registry states rather than collapsing them', () => {
    // The non-vacuity control for the rows above: an implementation that
    // stamped one constant satisfies every one of them individually.
    const seen = new Set(registries.map(([, tags, channel]) => sourceFor(tags, channel)));
    expect(seen.size).toBe(registries.length);
    expect(seen).toContain(RELEASE_TAG_SOURCE.Unpublished);
    expect(seen).toContain(RELEASE_TAG_SOURCE.Unknown);
  });

  it('leaves the field ABSENT on a plugin row whose latest came from a pin', () => {
    // The field describes the DIST-TAG resolution, and a pin displaces it — so
    // a value here would describe a version this row does not carry. Absent
    // rather than null, the way `marketplacePin` itself is absent when unset.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: '0.9.9' }),
      managedInstall: () => null,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    // The positive control: this really is the pin-wins row, so the absence
    // below is about the pin rather than about an empty report.
    expect(plugin?.latest).toBe('0.9.9');
    expect(plugin).toHaveProperty('marketplacePin');
    expect(plugin).not.toHaveProperty('latestFrom');
  });

  it('carries the field on a plugin row with no pin, which is what makes that absence mean something', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.10' }),
      installed: new Map([[REF, '0.9.8']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.9.10');
    expect(plugin).not.toHaveProperty('marketplacePin');
    expect(plugin?.latestFrom).toBe(
      sourceFor({ [DIST_TAG[RELEASE_CHANNEL.Stable]]: '0.9.10' }, RELEASE_CHANNEL.Stable),
    );
  });
});

// `channelLatest` is what a caller refusing an explicitly requested GRADUATED
// channel needs: `latest` on that row is the STABLE version that won the
// comparison, so without this the channel's own answer is nowhere on the row
// at all. Read from the same tag map `resolveChannel` was already given, so
// this costs no second registry request.
describe('gatherReport — the CLI row’s own channel tag, when the stable graduated past it', () => {
  it('carries the channel’s own tag beside the stable version that outranks it', () => {
    const report = gatherReport({
      viewDistTags: (pkg) => (pkg === CLI ? { latest: '0.12.0', beta: '0.11.0-beta.4' } : null),
      installed: new Map(),
      cliInstalled: '0.9.11',
      cliChannel: RELEASE_CHANNEL.Beta,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });

    const cli = report.statuses.find((s) => s.id === 'cli');
    expect(cli?.latestFrom).toBe(RELEASE_TAG_SOURCE.Graduated);
    expect(cli?.latest).toBe('0.12.0');
    expect(cli?.channelLatest).toBe('0.11.0-beta.4');
  });

  it.each([
    [
      'the channel’s own tag still leads — Channel, not Graduated',
      { latest: '0.9.12', beta: '0.11.0-beta.4' },
      RELEASE_CHANNEL.Beta,
    ],
    [
      'the channel publishes nothing — Unpublished, not Graduated',
      { latest: '0.9.12' },
      RELEASE_CHANNEL.Nightly,
    ],
    ['no tag map at all — Unknown, not Graduated', null, RELEASE_CHANNEL.Beta],
    [
      'the stable channel itself, which can never graduate past its own tag',
      { latest: '0.9.12' },
      RELEASE_CHANNEL.Stable,
    ],
  ] satisfies [string, DistTags | null, ReleaseChannel][])(
    'is ABSENT on every other source — %s',
    (_label, tags, channel) => {
      const report = gatherReport({
        viewDistTags: (pkg) => (pkg === CLI ? tags : null),
        installed: new Map(),
        cliInstalled: '0.9.11',
        cliChannel: channel,
        marketplacePin: () => ({ version: null }),
        managedInstall: () => null,
      });

      const cli = report.statuses.find((s) => s.id === 'cli');
      expect(cli?.latestFrom).not.toBe(RELEASE_TAG_SOURCE.Graduated);
      expect(cli).not.toHaveProperty('channelLatest');
    },
  );
});

// A plugin an organization's managed settings installed. Its version is the
// one the organization's marketplace declaration pins, and the host's own
// plugin autoupdate is what moves it — so the row reports what it runs and
// what the organization targets, and never offers `aka update` an install it
// must not drive. Every case holds npm AHEAD of what is installed, because npm
// being ahead is exactly what used to put the row in front of `aka update`.
describe('gatherReport — an install an organization manages', () => {
  const managed = (lookup: { version: string; ref?: string } | null) => (agent: { id: string }) =>
    agent.id === 'claude-code' ? lookup : null;

  it('reports the organization’s pin as the target, and offers no update', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.15' }),
      installed: new Map([[REF, '0.9.13']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: '0.9.14' }),
      managedInstall: managed({ version: '0.9.13', ref: 'org-release-8' }),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.installed).toBe('0.9.13');
    expect(plugin?.latest).toBe('0.9.14');
    expect(plugin?.updateAvailable).toBe(false);
    // Pending: the organization's pin is ahead and the host has yet to move.
    expect(plugin?.managedInstall).toEqual({ ref: 'org-release-8', pending: true });
    // Not a dist-tag resolution, so nothing may say it was one.
    expect(plugin).not.toHaveProperty('latestFrom');
  });

  it('is not pending once the host has installed the pin', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.15' }),
      installed: new Map([[REF, '0.9.14']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: '0.9.14' }),
      managedInstall: managed({ version: '0.9.14' }),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.updateAvailable).toBe(false);
    expect(plugin?.managedInstall).toEqual({ pending: false });
  });

  it.each([
    ['no pin could be read', { version: null }],
    ['the pin is a range', { version: null, range: '^0.9.0' }],
  ])('never offers npm’s latest as the target when %s', (_label, pin) => {
    // npm does not decide what a managed install runs — the organization's
    // declaration does — so with no exact pin in hand the target is unknown,
    // not npm's answer.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.15' }),
      installed: new Map([[REF, '0.9.13']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => pin,
      managedInstall: managed({ version: '0.9.13' }),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBeNull();
    expect(plugin?.updateAvailable).toBe(false);
    expect(plugin?.managedInstall).toEqual({ pending: false });
  });

  it('reports the managed copy’s version when a user copy sits beside it', () => {
    // `installed` is the comparison reader's projection, which prefers the
    // user record. The host resolves the managed one, so that is the version
    // this machine runs and the one the row must name.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.15' }),
      installed: new Map([[REF, '0.9.15']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: '0.9.14' }),
      managedInstall: managed({ version: '0.9.13' }),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.installed).toBe('0.9.13');
    expect(plugin?.managedInstall).toEqual({ pending: true });
    expect(plugin?.updateAvailable).toBe(false);
  });

  it('still asks npm, which is what the egress disclosure counts', () => {
    const asked: string[] = [];
    gatherReport({
      viewDistTags: (pkg) => {
        asked.push(pkg);
        return null;
      },
      installed: new Map([[REF, '0.9.13']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: '0.9.14' }),
      managedInstall: managed({ version: '0.9.13' }),
    });

    expect(asked).toContain(PLUGIN);
  });

  it('leaves an install nobody manages exactly as it was (positive control)', () => {
    // The same data with the seam answering null: the row offers the update,
    // so the refusals above come from the managed lookup and from nothing else
    // in the fixture.
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.15' }),
      installed: new Map([[REF, '0.9.13']]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: null }),
      managedInstall: managed(null),
    });

    const plugin = report.statuses.find((s) => s.id === 'claude-code');
    expect(plugin?.latest).toBe('0.9.15');
    expect(plugin?.updateAvailable).toBe(true);
    expect(plugin).not.toHaveProperty('managedInstall');
  });

  it('asks the seam per agent and applies its answer to that agent only', () => {
    const report = gatherReport({
      viewDistTags: views({ [CLI]: '0.0.1', [PLUGIN]: '0.9.15', [CODEX_PLUGIN]: '0.9.15' }),
      installed: new Map([
        [REF, '0.9.13'],
        ['aka-codex@ai-tc', '0.9.13'],
      ]),
      cliInstalled: '0.0.1',
      marketplacePin: () => ({ version: null }),
      managedInstall: managed({ version: '0.9.13' }),
    });

    const codex = report.statuses.find((s) => s.id === 'codex');
    expect(codex?.updateAvailable).toBe(true);
    expect(codex).not.toHaveProperty('managedInstall');
    expect(report.statuses.find((s) => s.id === 'claude-code')?.managedInstall).toBeDefined();
  });
});
