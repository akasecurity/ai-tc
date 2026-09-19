import { PageHead, relativeTime } from '@akasecurity/dashboard-ui';
import {
  AGENT_PLUGINS,
  createCliPluginManager,
  detectInstallChannel,
  installedPluginScope,
  planCliUpdate,
  pluginRef,
  readCache,
} from '@akasecurity/local-ops';
import { defaultDataDir } from '@akasecurity/persistence';

import { dashboardInstallOrigin } from '../../lib/install-origin';
import { renderInstant } from '../../lib/rendered-at';
import { cliUpdateTarget, updatesReport } from './report';
import type { UpdateAdvisory } from './UpdatesClient';
import { UpdatesClient } from './UpdatesClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Updates' };

export default function UpdatesPage() {
  // Page load never touches the network: `latest` comes from the passive-notice
  // cache, and "Check now" is what refreshes it via npm.
  const cache = readCache(defaultDataDir());
  const report = updatesReport(cache);

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
  //
  // The target — channel AND resolved version — is read off the report row this
  // page is about to render, through the same `cliUpdateTarget` that
  // `applyUpdate` in ./actions.ts calls. That shares the DERIVATION, not the
  // input: the action re-reads `readCache` at CLICK time rather than taking
  // what this render computed, so a cache rewritten in between (a background
  // refresh, or "Check now") can change what gets installed — the version this
  // line names is what the plan resolved to at render time, and the button may
  // resolve a newer one by the time it runs. A plan given only the channel
  // installed whatever that channel's dist-tag served instead, which is the
  // narrower defect this line does still prevent.
  const cliPlan = planCliUpdate(
    detectInstallChannel(dashboardInstallOrigin()),
    process.platform,
    cliUpdateTarget(report),
  );
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
    // Bound to the scope the plugin is really installed at: this page renders
    // the update command a user copies, and the version comparison beside it
    // reads a record at any scope while the host's update verb defaults to
    // `user`. A copied command that targets a different install than the
    // comparison did is the same defect, reached by hand.
    const manager = createCliPluginManager(agent.cliBin, installedPluginScope(ref));
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
