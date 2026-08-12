import { PageHead, relativeTime } from '@akasecurity/dashboard-ui';
import {
  AGENT_PLUGINS,
  CLI_PACKAGE,
  cliVersion,
  createCliPluginManager,
  gatherReport,
  installedAgentPluginVersions,
  pluginRef,
  readCache,
} from '@akasecurity/local-ops';
import { defaultDataDir } from '@akasecurity/persistence';
import type { UpdateCache } from '@akasecurity/schema';

import { UpdatesClient } from './UpdatesClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Updates' };

// Latest-version lookups by component id from the passive-notice cache — page
// load never touches the network; "Check now" refreshes the cache via npm.
function cachedLatestById(cache: UpdateCache | null): Map<string, string | null> {
  const latest = new Map<string, string | null>();
  if (!cache) return latest;
  for (const s of cache.report.statuses) latest.set(s.id, s.latest);
  for (const p of cache.report.availablePlugins) latest.set(p.id, p.latest);
  return latest;
}

export default function UpdatesPage() {
  const cache = readCache(defaultDataDir());
  const latestOf = cachedLatestById(cache);

  // Installed versions are read fresh (the ledger + this package's own
  // package.json); only `latest` comes from the cache.
  const report = gatherReport({
    viewVersion: (pkg) => {
      if (pkg === CLI_PACKAGE) return latestOf.get('cli') ?? null;
      const agent = AGENT_PLUGINS.find((a) => a.npmPackage === pkg);
      return agent ? (latestOf.get(agent.id) ?? null) : null;
    },
    installed: installedAgentPluginVersions(),
    cliInstalled: cliVersion(process.cwd()),
  });

  // EVERY command each button spawns, one per line — shown verbatim in the
  // confirm dialog. Two things this must get right:
  //
  // Derived from each agent's OWN host verb table, because the hosts share
  // neither the verbs (`claude plugin update` vs `codex plugin add`) nor the
  // binary — a hardcoded `claude …` here showed every Codex user a command
  // wrong on both counts.
  //
  // And it is the SPAWN PLAN, not the op alone: the Server Action runs the
  // marketplace prep first, so a dialog promising "this runs the following on
  // this machine" while naming one of three spawns is false in the direction
  // that matters for a local-first product. Newline-joined, never `&&` — the
  // plan carries a step whose failure the action deliberately ignores.
  const commands: Record<string, string> = {
    cli: `npm install -g ${CLI_PACKAGE}@latest`,
  };
  const installCommands: Record<string, string> = {};
  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    // No ref or no host binding means no automated path at all (Antigravity
    // installs from a local directory). Leaving the entry out would render an
    // EMPTY dialog under "this runs the following", which is a worse lie than
    // the wrong command it replaced, so say so instead.
    if (!ref || !agent.cliBin) {
      const none = `No automated path for ${agent.name} — see \`aka plugins install ${agent.id}\`.`;
      commands[agent.id] = none;
      installCommands[agent.id] = none;
      continue;
    }
    const manager = createCliPluginManager(agent.cliBin);
    const { marketplaceSource: source, marketplace } = agent;
    commands[agent.id] = manager.updateSpawnPlan(ref, source, marketplace).join('\n');
    installCommands[agent.id] = manager.installSpawnPlan(ref, source, marketplace).join('\n');
  }

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Updates"
        sub="Installed vs latest for the CLI and agent plugins — the web twin of `aka update`"
      />
      <UpdatesClient
        statuses={report.statuses}
        availablePlugins={report.availablePlugins}
        checkedAt={cache ? relativeTime(new Date(cache.checkedAt).toISOString()) : null}
        commands={commands}
        installCommands={installCommands}
      />
    </div>
  );
}
