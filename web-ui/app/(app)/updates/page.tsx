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

  // The exact command each button runs — shown verbatim in the confirm dialog.
  // Derived from each agent's OWN host verb table: the hosts do not share verbs
  // (`claude plugin update` vs `codex plugin add`) and they are not even the
  // same binary, so a hardcoded `claude …` here showed every Codex user a
  // command that fails on both counts.
  const commands: Record<string, string> = {
    cli: `npm install -g ${CLI_PACKAGE}@latest`,
  };
  const installCommands: Record<string, string> = {};
  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    if (!ref || !agent.cliBin) continue;
    const manager = createCliPluginManager(agent.cliBin);
    commands[agent.id] = manager.updateCommands(ref).join(' && ');
    installCommands[agent.id] = manager.installCommands(ref).join(' && ');
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
