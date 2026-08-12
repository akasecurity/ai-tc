import { type CliPluginBin, createCliPluginManager } from './cli-plugin-manager.ts';
import { runCapture, runInherit } from './exec.ts';
import { findAgent, pluginRef } from './registry.ts';
import { CLI_PACKAGE } from './updates.ts';

// Apply-side of the update surface, shared by `aka update` / `aka plugins
// install` and the web-ui's Updates page. One implementation of "validate id →
// resolve ref → ensure marketplace → run the package manager", with two output
// modes: 'inherit' streams to the caller's terminal (the CLI), 'capture'
// returns the combined output (the web-ui, which has no TTY to stream to).
//
// SECURITY: no user-controlled string ever reaches a child process. The only
// npm argument is the CLI_PACKAGE constant; plugin arguments are refs resolved
// from the static AGENT_PLUGINS registry after validating the caller-supplied
// id against it. An unknown id fails closed with no spawn.

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

function run(command: string, args: readonly string[], mode: ApplyMode): ApplyResult {
  if (mode === 'inherit') {
    return { ok: runInherit(command, [...args]), output: '' };
  }
  const res = runCapture(command, [...args], APPLY_TIMEOUT_MS);
  return { ok: res.ok, output: [res.stdout, res.stderr].filter(Boolean).join('\n') };
}

// Run a host's install/update steps in order, stopping at the first failure. A
// Codex update is two commands (snapshot refresh, then re-add), so this is a
// sequence rather than a single spawn; Claude Code's is a one-step case of it.
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

/** Self-update the globally installed CLI: `npm install -g @akasecurity/cli@latest`. */
export function applyCliUpdate(mode: ApplyMode = 'capture'): ApplyResult {
  return run('npm', ['install', '-g', `${CLI_PACKAGE}@latest`], mode);
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
    // command their CLI rejects.
    return {
      ok: false,
      output:
        `the \`${cliBin}\` CLI isn't on your PATH — install ${agent.name}, then run ` +
        `\`${manager.installCommands(ref).join(' && ')}\` (or update with ` +
        `\`${manager.updateCommands(ref, agent.marketplace).join(' && ')}\`).`,
    };
  }
  return {
    ref,
    cliBin,
    marketplace: agent.marketplace,
    marketplaceSource: agent.marketplaceSource,
  };
}

/** Update an installed agent plugin through its host CLI's own update path. */
export function applyPluginUpdate(agentId: string, mode: ApplyMode = 'capture'): ApplyResult {
  const resolved = resolveRef(agentId);
  if ('ok' in resolved) return resolved;
  const manager = createCliPluginManager(resolved.cliBin);
  if (resolved.marketplaceSource) manager.ensureMarketplace(resolved.marketplaceSource);
  return runSteps(resolved.cliBin, manager.updateSteps(resolved.ref, resolved.marketplace), mode);
}

/** Install an agent plugin through its host CLI (marketplace ensured first). */
export function installAgentPlugin(agentId: string, mode: ApplyMode = 'capture'): ApplyResult {
  const resolved = resolveRef(agentId);
  if ('ok' in resolved) return resolved;
  const manager = createCliPluginManager(resolved.cliBin);
  if (resolved.marketplaceSource) manager.ensureMarketplace(resolved.marketplaceSource);
  return runSteps(resolved.cliBin, manager.installSteps(resolved.ref), mode);
}
