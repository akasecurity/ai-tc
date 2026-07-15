import { PageHead, relativeTime } from '@akasecurity/dashboard-ui';
import {
  AGENT_PLUGINS,
  CLI_PACKAGE,
  cliVersion,
  gatherReport,
  installedPluginVersions,
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
    installed: installedPluginVersions(),
    cliInstalled: cliVersion(process.cwd()),
  });

  // The exact command each button runs — shown verbatim in the confirm dialog.
  const commands: Record<string, string> = {
    cli: `npm install -g ${CLI_PACKAGE}@latest`,
  };
  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    if (ref) commands[agent.id] = `claude plugin update ${ref}`;
  }
  const installCommands: Record<string, string> = {};
  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    if (ref) installCommands[agent.id] = `claude plugin install ${ref}`;
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
