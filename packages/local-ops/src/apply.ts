import { type CliPluginBin, createCliPluginManager } from './cli-plugin-manager.ts';
import { binExists, runCapture, runInherit } from './exec.ts';
import type { InstallChannel } from './install-channel.ts';
import { planCliUpdate } from './install-channel.ts';
import { findAgent, pluginRef } from './registry.ts';

// Apply-side of the update surface, shared by `aka update` / `aka plugins
// install` and the web-ui's Updates page. One implementation of "validate id →
// resolve ref → ensure marketplace → run the package manager", with two output
// modes: 'inherit' streams to the caller's terminal (the CLI), 'capture'
// returns the combined output (the web-ui, which has no TTY to stream to).
//
// SECURITY: no user-controlled string ever reaches a child process. The CLI
// update's arguments are the CLI_PACKAGE constant plus the install root the
// running code was found at — a path derived from the caller's own location on
// disk, never from argv, stdin or the environment; plugin arguments are refs
// resolved from the static AGENT_PLUGINS registry after validating the
// caller-supplied id against it. An unknown id fails closed with no spawn.
// The install root is the first argument here that is a PATH rather than a
// constant, which matters on Windows: exec.ts routes through cmd.exe there to
// resolve the `.cmd` shims, and Node does not quote argv under `shell: true`.
// exec.ts quotes it — see `quoteForShell`. POSIX spawns are shell-free.

export type ApplyMode = 'inherit' | 'capture';

export interface ApplyResult {
  ok: boolean;
  // Combined stdout+stderr in 'capture' mode (or the reason nothing ran);
  // empty in 'inherit' mode — the output already streamed to the terminal.
  output: string;
}

// Mutating package-manager runs can legitimately take minutes (npm i -g
// downloads the tarball + rebuilds the bin links); give them a generous cap so
// a slow registry doesn't strand a half-applied update.
const APPLY_TIMEOUT_MS = 10 * 60_000;

// Marketplace prep is a git fetch, not a package download, and it is the step a
// user is most likely to be waiting on with nothing to look at. Keep its own,
// much shorter cap so a hung fetch cannot sit on the ten-minute one — the op is
// what that budget is for.
const PREP_TIMEOUT_MS = 60_000;

function run(
  command: string,
  args: readonly string[],
  mode: ApplyMode,
  timeoutMs = APPLY_TIMEOUT_MS,
): ApplyResult {
  if (mode === 'inherit') {
    return { ok: runInherit(command, [...args]), output: '' };
  }
  const res = runCapture(command, [...args], timeoutMs);
  return { ok: res.ok, output: [res.stdout, res.stderr].filter(Boolean).join('\n') };
}

// Run a host's plugin-op steps in order, stopping at the first failure. Both
// hosts' ops are a single command today; this stays a sequence because the verb
// table returns one, and because a host whose op genuinely needs two commands
// must fail the whole operation if the first one fails. Marketplace prep is NOT
// run through here — see `prepare` for why it must not be fatal.
function runSteps(
  command: string,
  steps: readonly (readonly string[])[],
  mode: ApplyMode,
): ApplyResult {
  const outputs: string[] = [];
  for (const args of steps) {
    const res = run(command, args, mode);
    if (res.output) outputs.push(res.output);
    if (!res.ok) return { ok: false, output: outputs.join('\n') };
  }
  return { ok: true, output: outputs.join('\n') };
}

/**
 * Self-update the install described by `channel`. The package manager, and the
 * location it writes to, come from where the running code actually lives —
 * never from `npm` on PATH, which under nvm (or alongside a standalone binary)
 * installs a second copy the user never runs. Channels that cannot be updated
 * in-process — the standalone binary, Homebrew, a source checkout — return the
 * command that WOULD do it rather than running the wrong one.
 *
 * The channel is a parameter rather than detected here so that the plan a
 * caller PRINTS and the plan it RUNS are the same object; detecting twice
 * around a confirmation prompt lets the two disagree.
 */
export function applyCliUpdate(
  channel: InstallChannel,
  mode: ApplyMode = 'capture',
  // The PATH probe as a parameter, so the guard below can be driven without a
  // runnable channel reaching a real package manager on the developer's own
  // machine — the reason this file's other cases only ever drive refusals.
  hasBin: (bin: string) => boolean = binExists,
): ApplyResult {
  const plan = planCliUpdate(channel);
  if (plan.command === null) {
    return {
      ok: false,
      output: `Cannot update automatically: ${plan.reason ?? 'unsupported install'}.\nRun: ${plan.display}`,
    };
  }
  // The manager that OWNS the install need not be on PATH — a pnpm/yarn/bun
  // global keeps working after its manager is uninstalled, and the standalone
  // binary's `aka` is on PATH while no package manager may be. Without this,
  // the spawn fails ENOENT and both surfaces report the failure with nothing
  // in it: the dashboard renders an empty output panel, and the CLI prints
  // "see the bun output above" above nothing at all. `applyPluginUpdate`
  // already guards the identical case through `manager.available()`.
  const { bin, args } = plan.command;
  if (!hasBin(bin)) {
    return {
      ok: false,
      output: `the \`${bin}\` CLI isn't on your PATH — install it, then run: ${plan.display}`,
    };
  }
  return run(bin, args, mode);
}

// Resolve an agent id to its `<plugin>@<marketplace>` ref plus its bound
// cli-plugin-manager, failing closed on anything the static registry doesn't
// know or can't automate.
function resolveRef(agentId: string):
  | {
      ref: string;
      cliBin: CliPluginBin;
      marketplace?: string | undefined;
      marketplaceSource?: string | undefined;
    }
  | ApplyResult {
  const agent = findAgent(agentId);
  if (!agent) return { ok: false, output: `unknown agent '${agentId}'` };
  const ref = pluginRef(agent);
  const cliBin = agent.cliBin;
  if (!ref || !cliBin) {
    return { ok: false, output: `${agent.name} has no automated install path yet.` };
  }
  const manager = createCliPluginManager(cliBin);
  if (!manager.available()) {
    // Both hint commands come from the host's own verb table — the hosts do not
    // share verbs, so a hardcoded `plugin install` here would hand the user a
    // command their CLI rejects. They are RECIPES rather than bare plugin ops:
    // this branch means the host CLI isn't installed, so the marketplace has
    // almost certainly never been registered, and a line starting at
    // `plugin add` would fail on the unregistered marketplace.
    const source = agent.marketplaceSource;
    const install = manager.installRecipe(ref, source).join(' && ');
    const update = manager.updateRecipe(ref, source).join(' && ');
    // A host with no distinct update verb renders both identically (Codex
    // installs and updates with the same `plugin add`). Printing the same ~120
    // characters twice under "(or update with …)" reads as a rendering bug and
    // carries no information, so say it once and name what it covers.
    const how =
      install === update
        ? `\`${install}\` (that installs or updates)`
        : `\`${install}\` (or update with \`${update}\`)`;
    return {
      ok: false,
      output: `the \`${cliBin}\` CLI isn't on your PATH — install ${agent.name}, then run ${how}.`,
    };
  }
  return {
    ref,
    cliBin,
    marketplace: agent.marketplace,
    marketplaceSource: agent.marketplaceSource,
  };
}

// Marketplace prep runs before BOTH install and update, and is best-effort by
// design: registering an already-registered marketplace is a no-op, and a
// snapshot refresh that fails (offline, a git fetch error, a source that cannot
// be upgraded) leaves the cached snapshot in place — which the plugin op can
// still install from. Folding it into the fatal step list instead would let a
// failed refresh abort an operation that was going to succeed.
//
// It runs through the SAME mode-aware `run` as the op, which is the whole point
// rather than a tidy-up. Prep used to capture unconditionally, so in 'inherit'
// mode the CLI printed one line and then sat silent through two network-bound
// spawns — up to two minutes of a terminal showing nothing, which reads as a
// hang and invites a Ctrl-C in the middle of a marketplace write. Streaming is
// also what makes the announced plan honest: the user is told three commands
// will run, so all three have to be visible when they do.
//
// Each result is still discarded — that discard is the ONLY thing making prep
// survivable, so it must not turn into a chain on success.
function prepare(
  resolved: {
    cliBin: CliPluginBin;
    marketplace?: string | undefined;
    marketplaceSource?: string | undefined;
  },
  mode: ApplyMode,
): void {
  if (!resolved.marketplaceSource) return;
  const manager = createCliPluginManager(resolved.cliBin);
  for (const args of manager.marketplaceSteps(resolved.marketplaceSource, resolved.marketplace)) {
    run(resolved.cliBin, args, mode, PREP_TIMEOUT_MS);
  }
}

/** Update an installed agent plugin through its host CLI's own update path. */
export function applyPluginUpdate(agentId: string, mode: ApplyMode = 'capture'): ApplyResult {
  const resolved = resolveRef(agentId);
  if ('ok' in resolved) return resolved;
  prepare(resolved, mode);
  const manager = createCliPluginManager(resolved.cliBin);
  return runSteps(resolved.cliBin, manager.updateSteps(resolved.ref), mode);
}

/** Install an agent plugin through its host CLI (marketplace ensured first). */
export function installAgentPlugin(agentId: string, mode: ApplyMode = 'capture'): ApplyResult {
  const resolved = resolveRef(agentId);
  if ('ok' in resolved) return resolved;
  prepare(resolved, mode);
  const manager = createCliPluginManager(resolved.cliBin);
  return runSteps(resolved.cliBin, manager.installSteps(resolved.ref), mode);
}
