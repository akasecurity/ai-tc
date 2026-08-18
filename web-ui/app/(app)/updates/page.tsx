import { PageHead, relativeTime } from '@akasecurity/dashboard-ui';
import {
  AGENT_PLUGINS,
  CLI_PACKAGE,
  cliVersion,
  detectInstallChannel,
  gatherReport,
  installedAgentPluginVersions,
  planCliUpdate,
  pluginRef,
  readCache,
} from '@akasecurity/local-ops';
import { defaultDataDir } from '@akasecurity/persistence';
import type { UpdateCache } from '@akasecurity/schema';

import { dashboardInstallOrigin } from '../../lib/install-origin';
import type { UpdateAdvisory } from './UpdatesClient';
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
  // The CLI's command depends on how THIS copy was installed (npm global under
  // one nvm version, a pnpm/bun store, the standalone binary…), so it is derived
  // rather than assumed — the same plan the button will run. The origin comes
  // from this app, never from `import.meta.url`: see app/lib/install-origin.ts.
  //
  // A plan with no `command` is one this process will not run: the standalone
  // binary, a Homebrew tree, a source checkout. Its `display` is advice and is
  // kept OUT of `commands`, because the dialog introduces whatever it finds
  // there with "This runs the following command on this machine" — and for the
  // binary that line is the installer's curl-pipe-to-shell one-liner, which is
  // the last thing to present as something the dashboard is about to execute.
  const cliPlan = planCliUpdate(detectInstallChannel(dashboardInstallOrigin()));
  const commands: Record<string, string> = {};
  const advisories: Record<string, UpdateAdvisory> = {};
  if (cliPlan.command === null) {
    advisories.cli = {
      display: cliPlan.display,
      reason: cliPlan.reason ?? 'this copy cannot be updated from the dashboard',
    };
  } else {
    commands.cli = cliPlan.display;
  }
  //
  // A plugin's line is built from the registry the apply path resolves against,
  // never from a literal. Two things follow from that. The host CLI is per
  // agent (`claude` for Claude Code, `codex` for Codex), so naming one of them
  // here shows a command that is not the one that spawns — and a user who
  // copies it instead runs a real command against the wrong host. And both
  // apply paths register the marketplace BEFORE installing or updating, which
  // is a second child process and a persistent change to the host CLI's own
  // config, so it belongs in a dialog that says what will run.
  const installCommands: Record<string, string> = {};
  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    const bin = agent.cliBin;
    if (!ref || !bin) continue;
    const prelude = agent.marketplaceSource
      ? [`${bin} plugin marketplace add ${agent.marketplaceSource}`]
      : [];
    commands[agent.id] = [...prelude, `${bin} plugin update ${ref}`].join('\n');
    installCommands[agent.id] = [...prelude, `${bin} plugin install ${ref}`].join('\n');
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
        advisories={advisories}
        installCommands={installCommands}
      />
    </div>
  );
}
