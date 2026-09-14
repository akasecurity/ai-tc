import type * as LocalOps from '@akasecurity/local-ops';
import { AGENT_PLUGINS, createCliPluginManager, pluginRef } from '@akasecurity/local-ops';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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
// `installAgentPlugin` is stubbed because the announce line is printed BEFORE
// the spawn, and this suite is about the copy, not the child process.
const spawned = vi.hoisted(() => ({ calls: [] as string[] }));

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    createCliPluginManager: (bin: 'claude' | 'codex') => ({
      ...actual.createCliPluginManager(bin),
      available: () => true,
    }),
    installAgentPlugin: (agentId: string) => {
      spawned.calls.push(agentId);
      return { ok: true, output: '' };
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

beforeEach(() => {
  spawned.calls = [];
  process.exitCode = undefined;
});

afterEach(() => {
  process.exitCode = undefined;
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
