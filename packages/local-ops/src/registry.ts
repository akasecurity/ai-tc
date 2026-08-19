import type { SourceTool } from '@akasecurity/schema';

import type { CliPluginBin } from './cli-plugin-manager.ts';

// The plugin registry: the agent plugins the CLI hub knows how to surface. Plugins
// are INDEPENDENT peers — each self-installs and writes the shared local store,
// tagged with its SourceTool — and the CLI is an OPTIONAL hub over them, never a
// requirement. Adding an agent is a registry entry + a thin plugin app, not a CLI
// change. `sourceTool` joins an entry to the rows that agent records.
export interface AgentPlugin {
  id: string;
  name: string;
  sourceTool: SourceTool;
  description: string;
  // Install/update coordinates — present for agents distributed through a host
  // CLI's own plugin marketplace. `npmPackage` is the registry package the
  // marketplace resolves (used for `npm view <pkg> version` to learn the latest
  // version); `pluginName`@`marketplace` is the ref the host's install/update
  // verbs expect (they differ per host — see cli-plugin-manager.ts); and
  // `marketplaceSource` is the GitHub repo to `<cliBin> plugin marketplace add`
  // if the marketplace isn't registered yet. Absent for agents installed by
  // other means.
  npmPackage?: string;
  pluginName?: string;
  marketplace?: string;
  marketplaceSource?: string;
  // Which host CLI binary's plugin manager `apply.ts` should shell out to for
  // this agent's install/update coordinates. Only meaningful when the
  // coordinates above are present.
  cliBin?: CliPluginBin;
  // What to tell the user when there are no marketplace coordinates to drive.
  // Without one the CLI can only say "install it from the AKA marketplace",
  // which is wrong for a host that has no marketplace.
  installHint?: string;
}

export const AGENT_PLUGINS: readonly AgentPlugin[] = [
  {
    id: 'claude-code',
    name: 'Claude Code',
    sourceTool: 'claude-code',
    description:
      'Hooks Claude Code sessions to detect + redact sensitive data in prompts, responses, and file writes.',
    npmPackage: '@akasecurity/ai-tc-claude-code',
    pluginName: 'ai-tc',
    marketplace: 'akasecurity',
    marketplaceSource: 'akasecurity/marketplace',
    cliBin: 'claude',
  },
  {
    id: 'codex',
    name: 'Codex CLI',
    sourceTool: 'codex',
    description:
      'Hooks Codex CLI sessions to detect + redact sensitive data in prompts, responses, and Bash tool calls.',
    npmPackage: '@akasecurity/ai-tc-codex',
    // Distinct from Claude Code's `pluginName: 'ai-tc'` — ids from the two
    // registry entries flow into ONE ref-keyed `installed` lookup map
    // (see updates.ts/installedPluginVersions and apply.ts/resolveRef); an
    // identical ref for both would make either plugin's install ledger
    // entry satisfy the other's "is it installed" check.
    pluginName: 'aka-codex',
    // Codex CLI installs from this repo's own marketplace file; the canonical
    // akasecurity/marketplace repo currently carries Claude Code only.
    marketplace: 'ai-tc',
    marketplaceSource: 'akasecurity/ai-tc',
    cliBin: 'codex',
  },
  {
    id: 'antigravity',
    name: 'Antigravity',
    sourceTool: 'antigravity',
    description:
      'Hooks Antigravity CLI sessions to detect sensitive data in shell commands and file writes.',
    npmPackage: '@akasecurity/ai-tc-antigravity',
    // NO pluginName/marketplace/cliBin, deliberately. Antigravity has no plugin
    // marketplace: `agy plugin install` takes a LOCAL DIRECTORY PATH, not a
    // `<plugin>@<marketplace>` ref, so the generic cli-plugin-manager binding
    // the other two entries use would emit a command `agy` does not accept.
    // Leaving the coordinates absent is the registry's documented "installed by
    // other means" case — buildUpdateReport skips an entry with no ref, so this
    // agent is listed and joined to its rows by `sourceTool` without claiming an
    // update path that does not exist. Install is documented in
    // plugins/antigravity/skills/setup/SKILL.md.
    installHint:
      'Antigravity installs plugins from a local directory rather than a marketplace:\n' +
      '  npm pack @akasecurity/ai-tc-antigravity && tar -xzf akasecurity-ai-tc-antigravity-*.tgz\n' +
      '  agy plugin install ./package\n' +
      'Then run `aka init` to set up the local store.',
  },
];

export function findAgent(id: string): AgentPlugin | undefined {
  return AGENT_PLUGINS.find((a) => a.id === id);
}

// The `<plugin>@<marketplace>` ref every host's plugin verbs take, and the key
// under which Claude Code records the install in installed_plugins.json.
// Undefined for agents without marketplace coordinates.
export function pluginRef(agent: AgentPlugin): string | undefined {
  if (!agent.pluginName || !agent.marketplace) return undefined;
  return `${agent.pluginName}@${agent.marketplace}`;
}
