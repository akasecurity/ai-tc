import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import {
  AGENT_PLUGINS,
  createCliPluginManager,
  managedInstallRefusal,
  pluginRef,
} from '@akasecurity/local-ops';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

// What `aka plugins install` PRINTS before it spawns, which nothing else
// measures. local-ops proves the spawn plan matches the argv that really
// reaches the host (test/spawn.test.ts) and the Updates route proves the
// dashboard renders that same plan; this is the terminal's half of the same
// promise, and it is the surface where a user watches the commands scroll past
// and can notice one they were never told about.
//
// The announce line used to render the RECIPE — register-then-op, joined with
// `&&` — while three commands spawned, so the snapshot refresh ran undisclosed.
// Both renderings typecheck, are non-empty, and name the right host, so only an
// assertion tying the printed lines to `installSpawnPlan` can tell them apart.
//
// `available()` is forced rather than probed: the real one shells out to
// `command -v claude`, so this case would assert one thing on a developer's
// machine and skip the branch entirely on a CI runner without the host CLI.
// It answers true unless a case sets `spawned.available` to drive the
// not-on-PATH branch.
// `installAgentPlugin` is stubbed because the announce line is printed BEFORE
// the spawn, and this suite is about the copy, not the child process.
const spawned = vi.hoisted(() => ({
  calls: [] as string[],
  available: true,
  // What the stubbed shared apply does and returns. A case replaces it to stand
  // in for a refusal the shared path makes on its own, before any spawn.
  apply: (): { ok: boolean; output: string } => ({ ok: true, output: '' }),
}));

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    createCliPluginManager: (bin: 'claude' | 'codex') => ({
      ...actual.createCliPluginManager(bin),
      available: () => spawned.available,
    }),
    installAgentPlugin: (agentId: string) => {
      spawned.calls.push(agentId);
      return spawned.apply();
    },
  };
});

const { runPlugins } = await import('../../src/commands/plugins.ts');

async function captureAsync(fn: () => void | Promise<void>): Promise<string> {
  let out = '';
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
  return out;
}

// The install gate probes the host CLI's version. Injected as "unknown" here so
// these cases stay hermetic: the real probe shells out to `claude --version`,
// and this repo's PATH shims fail OPEN, so an unstubbed probe would reach the
// developer's own installed CLI and make the copy depend on their machine.
const NO_HOST_VERSION = { hostVersion: () => undefined };

// A controlled home. The command reads Claude Code's install ledger out of it
// to learn whether an organization manages the plugin, and without this every
// case here would depend on the ledger of whoever runs the suite: a machine
// with a managed install would see each install below refused. `os.homedir()`
// reads these two variables, and `n/no-process-env` is why the write goes
// through vitest rather than an assignment.
let home: string;

beforeEach(() => {
  spawned.calls = [];
  spawned.available = true;
  spawned.apply = () => ({ ok: true, output: '' });
  process.exitCode = undefined;
  home = mkdtempSync(join(tmpdir(), 'aka-plugins-install-'));
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
});

afterEach(() => {
  process.exitCode = undefined;
  vi.unstubAllEnvs();
  removeTree(home);
});

describe('aka plugins install discloses every command it is about to run', () => {
  // Both hosts, because their verbs differ and a single-host case passes while
  // the other renders a command its CLI rejects — the defect this table
  // replaced, reappearing in the copy a user reads.
  for (const agent of AGENT_PLUGINS) {
    const cliBin = agent.cliBin;
    const ref = pluginRef(agent);
    if (!cliBin || !ref) continue;
    const manager = createCliPluginManager(cliBin);

    it(`${agent.id}: names all of them, in order`, async () => {
      const plan = manager.installSpawnPlan(ref, agent.marketplaceSource, agent.marketplace);
      expect(plan.length).toBeGreaterThan(1);

      const out = await captureAsync(() => runPlugins(['install', agent.id], NO_HOST_VERSION));

      expect(spawned.calls).toEqual([agent.id]);
      for (const command of plan) expect(out).toContain(command);
      // In the plan's own order, so a render that lists the op before its prep
      // still fails — the order is the part a user checks against what scrolls
      // past next.
      const positions = plan.map((command) => out.indexOf(command));
      expect(positions).toEqual([...positions].sort((a, b) => a - b));
    });

    it(`${agent.id}: does not print the && recipe, which omits the refresh`, async (ctx) => {
      const recipe = manager.installRecipe(ref, agent.marketplaceSource);
      const plan = manager.installSpawnPlan(ref, agent.marketplaceSource, agent.marketplace);
      // Only meaningful where the two actually differ; where a host has no
      // refresh they are the same list and there is nothing to get wrong. A
      // skip rather than a return: a body that ends before its first assertion
      // has checked nothing, and reporting that as a pass is how a case that
      // stopped covering anything goes unnoticed.
      if (recipe.length === plan.length) {
        ctx.skip(`${agent.id}: recipe and spawn plan are the same list`);
      }

      const out = await captureAsync(() => runPlugins(['install', agent.id], NO_HOST_VERSION));

      expect(out).not.toContain(recipe.join(' && '));
    });
  }
});

// A scripted Prompter: answers come from a queue, output is captured.
function fakePrompter(answers: string[], isInteractive = true): Prompter & { out_: string[] } {
  const out_: string[] = [];
  return {
    out_,
    out: (t) => out_.push(t),
    err: (t) => out_.push(t),
    isInteractive,
    ask: () => Promise.resolve(answers.shift() ?? ''),
    askHidden: () => Promise.resolve(''),
    readAllStdin: () => Promise.resolve(''),
  };
}

describe('aka plugins install warns when Claude Code is too old for part of AKA', () => {
  // An old host DROPS the hook entries it does not recognise and loads the
  // rest, so without this the install is clean and a protection is silently
  // absent — which is exactly how this was discovered.
  const ANCIENT = '2.0.0';

  it('names the protections at risk and does not install when declined', async () => {
    const io = fakePrompter(['n']);
    await runPlugins(['install', 'claude-code'], { hostVersion: () => ANCIENT, prompter: io });
    const printed = io.out_.join('');
    expect(printed).toContain(ANCIENT);
    expect(printed).toContain('model-switch protection');
    expect(printed).toContain('Not installed');
    expect(spawned.calls).toEqual([]);
    // Non-zero, or `aka plugins install … && aka init` treats a decline as a
    // successful install and carries on.
    expect(process.exitCode).toBe(1);
  });

  it('installs anyway when the user says yes', async () => {
    const io = fakePrompter(['y']);
    await runPlugins(['install', 'claude-code'], { hostVersion: () => ANCIENT, prompter: io });
    expect(spawned.calls).toEqual(['claude-code']);
    expect(process.exitCode).toBeUndefined();
  });

  it('warns but does not block a non-interactive install', async () => {
    // A script or CI run cannot answer a question; hanging or refusing there
    // would be worse than proceeding with the warning on the record.
    const io = fakePrompter([], false);
    await runPlugins(['install', 'claude-code'], { hostVersion: () => ANCIENT, prompter: io });
    expect(io.out_.join('')).toContain('older than AKA needs');
    expect(spawned.calls).toEqual(['claude-code']);
  });

  it('says NOTHING about the host on a current one', async () => {
    // The non-vacuity control: without it every assertion above is satisfied
    // by a gate that warns unconditionally.
    const io = fakePrompter([]);
    await runPlugins(['install', 'claude-code'], { hostVersion: () => '99.0.0', prompter: io });
    expect(io.out_).toEqual([]);
    expect(spawned.calls).toEqual(['claude-code']);
  });

  it('says nothing when the host version cannot be read, and still installs', async () => {
    // Fail-silent: a false "update Claude Code" on a correct install costs
    // more than a missed warning.
    const io = fakePrompter([]);
    await runPlugins(['install', 'claude-code'], { hostVersion: () => undefined, prompter: io });
    expect(io.out_).toEqual([]);
    expect(spawned.calls).toEqual(['claude-code']);
  });

  it('does not gate a non-Claude-Code host on Claude Code floors', async () => {
    // These floors are Claude Code hook events; applying them to Codex would
    // warn about a protection that host never delivers through them.
    const io = fakePrompter([]);
    await runPlugins(['install', 'codex'], { hostVersion: () => ANCIENT, prompter: io });
    expect(io.out_).toEqual([]);
    expect(spawned.calls).toEqual(['codex']);
  });
});

describe('who owns the exit code when the floor prompt is declined', () => {
  it('reports failure for a direct `aka plugins install`', async () => {
    // The decline IS the operation here, so `aka plugins install … && aka init`
    // must not carry on. This is the default, with no flag passed.
    const io = fakePrompter(['n']);
    await runPlugins(['install', 'claude-code'], { hostVersion: () => '2.0.0', prompter: io });
    expect(spawned.calls).toEqual([]);
    expect(process.exitCode).toBe(1);
  });

  it('does NOT fail the command when the caller says a decline is skippable', async () => {
    // `aka init` offers the plugin as an optional extra AFTER the store is built.
    // Declining is a skip, exactly like init's own decline path, so init must
    // still exit 0 — it succeeded.
    const io = fakePrompter(['n']);
    await runPlugins(['install', 'claude-code'], {
      hostVersion: () => '2.0.0',
      prompter: io,
      declineIsFailure: false,
    });
    expect(io.out_.join('')).toContain('Not installed');
    expect(spawned.calls).toEqual([]);
    expect(process.exitCode).toBeUndefined();
  });
});

describe('the install gate respects consent already given', () => {
  it('warns but does not ask when the caller passed --yes', async () => {
    // `aka init --yes` threads assumeYes. Without it the gate re-asks a user who
    // passed --yes precisely to avoid being asked, and a scripted Enter answers
    // "no" — so --yes would install nothing.
    const io = fakePrompter([], true);
    await runPlugins(['install', 'claude-code'], {
      hostVersion: () => '2.0.0',
      prompter: io,
      assumeYes: true,
    });
    expect(io.out_.join('')).toContain('older than AKA needs');
    expect(spawned.calls).toEqual(['claude-code']);
    expect(process.exitCode).toBeUndefined();
  });
});

/** Seed Claude Code's install ledger for the AKA plugin inside the stubbed home. */
function writeLedger(records: unknown[]): void {
  const dir = join(home, '.claude', 'plugins');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'ai-tc@akasecurity': records } }),
  );
}

async function captureBoth(fn: () => void | Promise<void>): Promise<{ out: string; err: string }> {
  let err = '';
  const spy = vi
    .spyOn(process.stderr, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  try {
    const out = await captureAsync(fn);
    return { out, err };
  } finally {
    spy.mockRestore();
  }
}

// On a machine where an organization's managed settings installed the plugin.
// The install path's first spawn is `claude plugin marketplace add` with no
// ref, which a host that accepts it turns into an unpinned registration in
// place of the organization's pinned one. So nothing is announced, nothing is
// asked and nothing reaches the apply seam: the refusal is the whole output.
describe('aka plugins install over an install an organization manages', () => {
  it('refuses before announcing anything, and fails the command', async () => {
    writeLedger([{ scope: 'managed', version: '0.9.14' }]);

    const { out, err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(spawned.calls).toEqual([]);
    expect(out).toBe('');
    expect(err).toBe(`aka plugins install: ${managedInstallRefusal('Claude Code')}\n`);
    // Non-zero because the install that was asked for did not happen. The
    // plugin IS on the machine, but not by this command, and a script reading
    // success as "I installed it" would be told something untrue.
    expect(process.exitCode).toBe(1);
  });

  it('refuses before the host-floor question, which would ask about an install that cannot happen', async () => {
    writeLedger([{ scope: 'managed', version: '0.9.14' }]);
    const hostVersion = vi.fn(() => '2.0.0');
    const io = fakePrompter(['y']);

    await captureBoth(() => runPlugins(['install', 'claude-code'], { hostVersion, prompter: io }));

    expect(hostVersion).not.toHaveBeenCalled();
    expect(io.out_).toEqual([]);
    expect(spawned.calls).toEqual([]);
    expect(process.exitCode).toBe(1);
  });

  it('refuses where `claude` is not on PATH, instead of printing a recipe to run by hand', async () => {
    // That recipe starts with the same unpinned `marketplace add`, so typing
    // it in does exactly what the refusal exists to prevent.
    writeLedger([{ scope: 'managed', version: '0.9.14' }]);
    spawned.available = false;

    const { out, err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(out).not.toContain('marketplace add');
    expect(err).toContain(managedInstallRefusal('Claude Code'));
    expect(process.exitCode).toBe(1);
  });

  it('refuses a managed record that names no version', async () => {
    writeLedger([{ scope: 'managed' }]);

    const { out, err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(spawned.calls).toEqual([]);
    expect(out).toBe('');
    expect(err).toContain(managedInstallRefusal('Claude Code'));
    expect(process.exitCode).toBe(1);
  });

  it('installs over a user-scope record exactly as before (positive control)', async () => {
    writeLedger([{ scope: 'user', version: '0.9.14' }]);

    const { out, err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(spawned.calls).toEqual(['claude-code']);
    expect(out).toContain('Installed Claude Code');
    expect(err).toBe('');
    expect(process.exitCode).toBeUndefined();
  });

  it('installs where the ledger names no install of it (positive control)', async () => {
    // The ledger exists and was parsed; it just has nothing for this ref.
    const dir = join(home, '.claude', 'plugins');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'installed_plugins.json'),
      JSON.stringify({ version: 2, plugins: { 'other@elsewhere': [{ scope: 'managed' }] } }),
    );

    const { err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(spawned.calls).toEqual(['claude-code']);
    expect(err).toBe('');
    expect(process.exitCode).toBeUndefined();
  });
});

// The ledger read at the top of the command and the one inside the shared
// apply are two moments, and between them the command can wait on a human: the
// host-floor question. A managed record landing in that gap (the organization's
// drop-in arriving, or the host's own autoupdate rewriting the ledger) must not
// get the announce line for three commands that never run, and must never be
// answered with the fallback recipe, which opens with the unpinned
// `marketplace add` for the user to paste by hand.
describe('aka plugins install when the plugin becomes managed mid-command', () => {
  const MANAGED = [{ scope: 'managed', version: '0.9.14' }];

  it('refuses before announcing when the record lands during the floor question', async () => {
    const io: Prompter & { out_: string[] } = {
      ...fakePrompter([]),
      ask: () => {
        writeLedger(MANAGED);
        return Promise.resolve('y');
      },
    };

    const { out, err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], { hostVersion: () => '2.0.0', prompter: io }),
    );

    expect(spawned.calls).toEqual([]);
    expect(out).not.toContain('running:');
    expect(err).toContain(managedInstallRefusal('Claude Code'));
    expect(process.exitCode).toBe(1);
  });

  it('prints the shared refusal, and no recipe, when the record lands during the apply', async () => {
    spawned.apply = () => {
      writeLedger(MANAGED);
      return { ok: false, output: managedInstallRefusal('Claude Code') };
    };

    const { out, err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    // The positive control that the apply was reached, so the refusal below
    // is the shared path's rather than one of the command's own checks.
    expect(spawned.calls).toEqual(['claude-code']);
    expect(err).toContain(managedInstallRefusal('Claude Code'));
    expect(err).not.toContain('marketplace add');
    // Only the announce line may name it, and that line printed before the
    // record existed.
    expect(out.split('marketplace add').length - 1).toBe(1);
    expect(err).not.toContain('see the output above');
    expect(process.exitCode).toBe(1);
  });

  it('prints any other refusal the shared path returns before spawning', async () => {
    // Inherit mode streams what the host printed, so `output` is non-empty only
    // for a refusal made before any spawn, and then it is the one explanation.
    spawned.apply = () => ({ ok: false, output: 'the shared path said why' });

    const { err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(err).toContain('the shared path said why');
    expect(err).not.toContain('see the output above');
    expect(process.exitCode).toBe(1);
  });

  it('keeps the recipe for a spawn that failed on a machine nobody manages (positive control)', async () => {
    spawned.apply = () => ({ ok: false, output: '' });

    const { err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], NO_HOST_VERSION),
    );

    expect(err).toContain('Install failed — see the output above');
    expect(err).toContain('claude plugin marketplace add akasecurity/marketplace');
    expect(process.exitCode).toBe(1);
  });
});

// `aka init` offers the plugin as an optional extra once its own work is done,
// and passes `declineIsFailure: false` so passing on it does not fail init. An
// install the organization already manages is the same outcome for init:
// nothing installed and nothing wrong, the plugin already present.
describe('who owns the exit code when the organization already manages the plugin', () => {
  it('does not fail `aka init` for it', async () => {
    writeLedger([{ scope: 'managed', version: '0.9.14' }]);

    const { err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], { ...NO_HOST_VERSION, declineIsFailure: false }),
    );

    expect(spawned.calls).toEqual([]);
    expect(err).toContain(managedInstallRefusal('Claude Code'));
    expect(process.exitCode).toBeUndefined();
  });

  it('does not fail `aka init` when the record lands during the apply', async () => {
    spawned.apply = () => {
      writeLedger([{ scope: 'managed', version: '0.9.14' }]);
      return { ok: false, output: managedInstallRefusal('Claude Code') };
    };

    const { err } = await captureBoth(() =>
      runPlugins(['install', 'claude-code'], { ...NO_HOST_VERSION, declineIsFailure: false }),
    );

    expect(err).toContain(managedInstallRefusal('Claude Code'));
    expect(process.exitCode).toBeUndefined();
  });

  it('still fails `aka init` for a genuine install failure (positive control)', async () => {
    // The flag covers the two outcomes where nothing went wrong, not every
    // failure, so a broken install still reports non-zero to init.
    spawned.apply = () => ({ ok: false, output: '' });

    await captureBoth(() =>
      runPlugins(['install', 'claude-code'], { ...NO_HOST_VERSION, declineIsFailure: false }),
    );

    expect(process.exitCode).toBe(1);
  });
});
