import { DIST_TAG, RELEASE_CHANNEL } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { applyCliUpdate, applyPluginUpdate, installAgentPlugin } from '../src/apply.ts';
import type { InstallChannel } from '../src/install-channel.ts';
import { SEA_OWNER } from '../src/install-channel.ts';
import { CLI_PACKAGE } from '../src/updates.ts';

// The mutating paths (npm / claude spawns) are exercised end-to-end by `aka
// update`; here we pin the fail-closed validation — no child process may ever
// run for an id the static registry doesn't know.

// A channel that cannot be updated in-process must be REFUSED, not run. Only
// the refusing channels are driven through applyCliUpdate here: a runnable one
// would spawn the real package manager against the developer's own machine,
// which is why the runnable half is asserted on `planCliUpdate` instead
// (src/install-channel.test.ts) where no spawn is reachable.
describe('applyCliUpdate refuses a channel it cannot update', () => {
  const refusing: [string, InstallChannel][] = [
    [
      'sea',
      {
        kind: 'sea',
        execPath: '/usr/local/bin/aka',
        managedBy: SEA_OWNER.Standalone,
        installRoot: null,
      },
    ],
    // The binary's other two owners refuse for a different reason — a package
    // manager holds the files — and each has an update command of its own, so a
    // plan that gained one would reach a spawn here rather than advice.
    [
      'sea/homebrew',
      {
        kind: 'sea',
        execPath: '/opt/homebrew/Cellar/aka/0.9.13/libexec/aka-darwin-arm64/aka',
        managedBy: SEA_OWNER.Homebrew,
        installRoot: null,
      },
    ],
    [
      'sea/scoop',
      {
        kind: 'sea',
        execPath: 'C:/Users/u/scoop/apps/aka/current/aka.exe',
        managedBy: SEA_OWNER.Scoop,
        installRoot: null,
      },
    ],
    ['homebrew', { kind: 'homebrew', packageDir: '/opt/homebrew/Cellar/aka/0.9.3' }],
    ['dev', { kind: 'dev', packageDir: '/src/ai-tc' }],
    ['unknown', { kind: 'unknown', detail: 'nowhere in particular' }],
  ];

  for (const [name, channel] of refusing) {
    it(`returns advice rather than spawning for a ${name} install`, () => {
      // Reaching a spawn at all is the failure: every one of these has a null
      // command, so an unguarded `plan.command.bin` throws instead of refusing.
      //
      // The PATH probe answers false so that falsifying this cannot run a real
      // package manager on the developer's own machine. It changes nothing while
      // the plan refuses — `plan.command === null` returns before the probe is
      // consulted — and a plan that stopped refusing reports the missing binary
      // instead, which reddens these assertions with no child process started.
      const res = applyCliUpdate(channel, 'capture', () => false);
      expect(res.ok).toBe(false);
      expect(res.output).toContain('Cannot update automatically');
      expect(res.output).toContain('Run:');
      // Never the blind global install this surface used to run unconditionally.
      expect(res.output).not.toContain('npm install -g @akasecurity/cli@latest\n');
    });
  }

  it('names what to run instead, so the refusal is actionable', () => {
    const sea = applyCliUpdate(
      {
        kind: 'sea',
        execPath: '/usr/local/bin/aka',
        managedBy: SEA_OWNER.Standalone,
        installRoot: null,
      },
      'capture',
      () => false,
    );
    expect(sea.output).toContain('install.');

    // Each owner is named its own command rather than the installer's, which is
    // the whole point of carrying the owner: unpacking the archive over a tree
    // brew or scoop owns leaves a second copy they then fight over.
    const brew = applyCliUpdate(
      {
        kind: 'sea',
        execPath: '/opt/homebrew/Cellar/aka/0.9.13/libexec/aka-darwin-arm64/aka',
        managedBy: SEA_OWNER.Homebrew,
        installRoot: null,
      },
      'capture',
      () => false,
    );
    expect(brew.output).toContain('brew upgrade aka');
    expect(brew.output).not.toContain('install.sh');

    const scoop = applyCliUpdate(
      {
        kind: 'sea',
        execPath: 'C:/Users/u/scoop/apps/aka/current/aka.exe',
        managedBy: SEA_OWNER.Scoop,
        installRoot: null,
      },
      'capture',
      () => false,
    );
    expect(scoop.output).toContain('scoop update aka');
    expect(scoop.output).not.toContain('install.ps1');
  });
});

describe('applyCliUpdate refuses a manager that is not on PATH', () => {
  // The manager that OWNS an install need not be runnable here: a pnpm/yarn/bun
  // global keeps working after its manager is uninstalled. Without the guard the
  // spawn fails ENOENT and `run` reports `{ ok: false, output: '' }` — the
  // dashboard renders an empty failure panel and the CLI prints "see the bun
  // output above" above nothing.
  //
  // Driven through the injected probe rather than by arranging a real PATH, so
  // no runnable channel can reach a real `npm install -g` here.
  const global: InstallChannel = {
    kind: 'global',
    manager: 'bun',
    root: '/home/u/.bun/install/global',
    packageDir: '/home/u/.bun/install/global/node_modules/@akasecurity/cli',
  };

  it('says which CLI is missing, and what to run once it is back', () => {
    const res = applyCliUpdate(global, 'capture', () => false);
    expect(res.ok).toBe(false);
    expect(res.output).toContain('bun');
    expect(res.output).toContain("isn't on your PATH");
    // The actionable half: an empty output is the defect this replaced.
    expect(res.output).toContain('bun add -g');
  });

  it('probes the manager the plan will actually run, not a hardcoded one', () => {
    const asked: string[] = [];
    applyCliUpdate(global, 'capture', (bin) => {
      asked.push(bin);
      return false;
    });
    expect(asked).toStrictEqual(['bun']);
  });

  it('probes nothing for a channel that was refused before any command existed', () => {
    // The order matters: a refusing channel has no `command`, so a probe here
    // would be dereferencing it.
    const asked: string[] = [];
    const res = applyCliUpdate({ kind: 'dev', packageDir: '/src/ai-tc' }, 'capture', (bin) => {
      asked.push(bin);
      return true;
    });
    expect(asked).toStrictEqual([]);
    expect(res.output).toContain('Cannot update automatically');
  });
});

/**
 * The release channel reaches the plan this function RUNS.
 *
 * Its caller builds a plan of its own to print, so a channel that is threaded
 * into that one and dropped here prints `@beta` and installs `@latest` — and
 * the dashboard's apply action prints nothing, so there the value handed here
 * is the only thing that decides. Neither the plan's own suite nor the
 * command's can see it: one never calls this, and the other stubs it.
 *
 * Driven through the PATH probe so the tag is read off a refusal rather than
 * out of a spawn — the same reason every other runnable-channel case here
 * refuses.
 */
describe('applyCliUpdate carries the target into the plan it runs', () => {
  const global: InstallChannel = {
    kind: 'global',
    manager: 'npm',
    root: '/opt/node',
    packageDir: '/opt/node/lib/node_modules/@akasecurity/cli',
  };

  it('asks for the requested channel tag when no version was resolved', () => {
    const res = applyCliUpdate(global, 'capture', () => false, {
      channel: RELEASE_CHANNEL.Beta,
      version: null,
    });
    expect(res.ok).toBe(false);
    // The positive control first: an empty output satisfies the absence below.
    expect(res.output).toContain(`${CLI_PACKAGE}@beta`);
    expect(res.output).not.toContain(`${CLI_PACKAGE}@latest`);
  });

  it('asks for the RESOLVED version when the report resolved one', () => {
    // The graduation row, reached through this entry point rather than only
    // through `planCliUpdate`: the version has to survive the whole call, and a
    // parameter dropped here is the same defect one frame further in.
    const res = applyCliUpdate(global, 'capture', () => false, {
      channel: RELEASE_CHANNEL.Beta,
      version: '0.11.0',
    });
    expect(res.output).toContain(`${CLI_PACKAGE}@0.11.0`);
    expect(res.output).not.toContain(`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`);
  });

  it('treats a version this grammar refuses as unresolved', () => {
    // A registry answer carrying a shell metacharacter never reaches the spec;
    // the plan falls back to the closed dist-tag table instead.
    const res = applyCliUpdate(global, 'capture', () => false, {
      channel: RELEASE_CHANNEL.Beta,
      version: '0.11.0; id',
    });
    expect(res.output).toContain(`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`);
    expect(res.output).not.toContain('; id');
  });

  it('asks for the stable tag when nothing was requested', () => {
    // The default has to stay what shipped — every existing caller omits it.
    const res = applyCliUpdate(global, 'capture', () => false);
    expect(res.output).toContain(`${CLI_PACKAGE}@latest`);
    expect(res.output).not.toContain(`${CLI_PACKAGE}@beta`);
    expect(res).toStrictEqual(
      applyCliUpdate(global, 'capture', () => false, {
        channel: RELEASE_CHANNEL.Stable,
        version: null,
      }),
    );
  });

  it('keeps the probe seam and the target independent', () => {
    // The target is the LAST parameter, so a caller that passes it has to pass
    // `hasBin` too — and the probe must still be the injected one rather than
    // the real PATH lookup, or this case reaches the developer's own npm.
    const asked: string[] = [];
    applyCliUpdate(
      global,
      'capture',
      (bin) => {
        asked.push(bin);
        return false;
      },
      { channel: RELEASE_CHANNEL.Nightly, version: '0.9.13-nightly.20260918.gabc1234' },
    );
    expect(asked).toStrictEqual(['npm']);
  });
});

describe('applyPluginUpdate / installAgentPlugin id validation', () => {
  it('fails closed on an unknown agent id', () => {
    const res = applyPluginUpdate('definitely-not-an-agent');
    expect(res.ok).toBe(false);
    expect(res.output).toContain('unknown agent');
  });

  it('never treats flag-like input as installable', () => {
    const res = installAgentPlugin('--registry=https://evil.example');
    expect(res.ok).toBe(false);
    expect(res.output).toContain('unknown agent');
  });
});
