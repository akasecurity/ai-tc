import { PageHead, relativeTime } from '@akasecurity/dashboard-ui';
import {
  AGENT_PLUGINS,
  CLI_PACKAGE,
  cliVersion,
  createCliPluginManager,
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
import { renderInstant } from '../../lib/rendered-at';
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

  // EVERY command each plugin button spawns, one per line. Two things this must
  // get right, and a literal gets both wrong:
  //
  // It is derived from each agent's OWN host verb table, because the hosts share
  // neither the verbs (`claude plugin update` vs `codex plugin add` — Codex has
  // no update verb at all) nor the binary. A hardcoded `${bin} plugin update`
  // shows every Codex user a command their CLI rejects, and one they may copy
  // and run against the real host.
  //
  // And it is the SPAWN PLAN, not the op with a register prelude: the Server
  // Action refreshes the marketplace snapshot too, so a dialog promising "this
  // runs the following on this machine" while naming two of three spawns is
  // false in the direction that matters for a local-first product.
  // Newline-joined, never `&&` — the plan carries a step whose failure the
  // action deliberately ignores.
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

  // Captured once, per this file's own contract ("call once per request"),
  // rather than inline in the prop below — harmless with the one label this
  // page derives today, but an inline call is a landmine for whichever
  // second time-derived value lands on this page next.
  const renderedAt = renderInstant();

  return (
    <div className="p-6">
      <PageHead
        title="Updates"
        sub="Installed vs latest for the CLI and agent plugins — the web twin of `aka update`"
      />
      <UpdatesClient
        statuses={report.statuses}
        availablePlugins={report.availablePlugins}
        // Resolved to a STRING here rather than in the client component: the
        // label crosses the boundary already formatted, so the browser has
        // nothing to recompute and nothing to disagree with.
        checkedAt={cache ? relativeTime(new Date(cache.checkedAt).toISOString(), renderedAt) : null}
        commands={commands}
        advisories={advisories}
        installCommands={installCommands}
      />
    </div>
  );
}
