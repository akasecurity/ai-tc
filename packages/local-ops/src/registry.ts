import type { SourceTool } from '@akasecurity/schema';

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
  // Install/update coordinates — present for agents distributed through the Claude
  // Code plugin marketplace. `npmPackage` is the registry package the marketplace
  // resolves (used for `npm view <pkg> version` to learn the latest version);
  // `pluginName`@`marketplace` is the ref `claude plugin install|update` expects; and
  // `marketplaceSource` is the GitHub repo to `claude plugin marketplace add` if the
  // marketplace isn't registered yet. Absent for agents installed by other means.
  npmPackage?: string;
  pluginName?: string;
  marketplace?: string;
  marketplaceSource?: string;
}

export const AGENT_PLUGINS: readonly AgentPlugin[] = [
  {
    id: 'claude-code',
    name: 'Claude Code',
    sourceTool: 'claude-code',
    description:
      'Hooks Claude Code sessions to detect + redact sensitive data in prompts, responses, and file writes.',
    npmPackage: '@akasecurity/plugin-claude-code',
    pluginName: 'aka',
    marketplace: 'ai-tc',
    marketplaceSource: 'akasecurity/ai-tc',
  },
];

export function findAgent(id: string): AgentPlugin | undefined {
  return AGENT_PLUGINS.find((a) => a.id === id);
}

// The `<plugin>@<marketplace>` ref that `claude plugin install|update` expects, and
// the key under which Claude Code records the install in installed_plugins.json.
// Undefined for agents without marketplace coordinates.
export function pluginRef(agent: AgentPlugin): string | undefined {
  if (!agent.pluginName || !agent.marketplace) return undefined;
  return `${agent.pluginName}@${agent.marketplace}`;
}
