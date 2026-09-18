import {
  AGENT_PLUGINS,
  CLI_PACKAGE,
  cliVersion,
  gatherReport,
  installedAgentPluginVersions,
  marketplacePinnedVersion,
} from '@akasecurity/local-ops';
import type { CliUpdateTarget, UpdateCache, UpdateReport } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL } from '@akasecurity/schema';

// The Updates surface's one derivation of "what is installed, what is available,
// and what the CLI button would install", shared by ./page.tsx and ./actions.ts.
//
// It is shared rather than written twice because the two are the halves of one
// promise: the page renders a dialog introducing its line with "This runs the
// following command on this machine", and the action is what then runs it. Two
// derivations of the same thing agree only while somebody keeps them in step,
// and the version in that line is exactly what went out of step — the dialog
// named the version the report resolved while the install asked npm for the
// channel's dist-tag, which on a graduating prerelease is a different release.
//
// Nothing here opens a connection: `latest` comes from the passive-notice cache
// the CLI wrote, and everything else is a local file read.

// Latest-version lookups by component id from the passive-notice cache.
function cachedLatestById(cache: UpdateCache | null): Map<string, string | null> {
  const latest = new Map<string, string | null>();
  if (!cache) return latest;
  for (const s of cache.report.statuses) latest.set(s.id, s.latest);
  for (const p of cache.report.availablePlugins) latest.set(p.id, p.latest);
  return latest;
}

// The cached latest for one npm package name, resolved through the registry
// entry that declares it — the report asks by package name, the cache is keyed
// by component id.
function cachedLatestFor(latestOf: Map<string, string | null>, pkg: string): string | null {
  if (pkg === CLI_PACKAGE) return latestOf.get('cli') ?? null;
  const agent = AGENT_PLUGINS.find((a) => a.npmPackage === pkg);
  return agent ? (latestOf.get(agent.id) ?? null) : null;
}

/**
 * The update report this route renders, built over the cache the caller read.
 *
 * Installed versions are read fresh (the ledger + this package's own
 * package.json); only `latest` comes from the cache.
 */
export function updatesReport(cache: UpdateCache | null): UpdateReport {
  const latestOf = cachedLatestById(cache);
  return gatherReport({
    // The cached `latest` was ALREADY channel-resolved when the CLI's
    // background refresh wrote it, so it is handed back as a single-tag map
    // spelled `latest`. The resolution takes the max of the channel tag and
    // `latest` and falls back when the channel tag is missing, so a beta
    // machine's cached beta version resolves to itself with no special case
    // here — and this page still opens no connection of its own.
    viewDistTags: (pkg) => {
      const cached = cachedLatestFor(latestOf, pkg);
      return cached === null ? null : { [DIST_TAG[RELEASE_CHANNEL.Stable]]: cached };
    },
    installed: installedAgentPluginVersions(),
    cliInstalled: cliVersion(process.cwd()),
    // Read live rather than from the cache, unlike `latest` above: the pin is a
    // local file the host itself wrote, so there is no request to amortise, and
    // a stale pin would put this page back to offering an update the host
    // cannot deliver — the defect the pin exists to close.
    marketplacePin: (agent) => marketplacePinnedVersion(agent),
  });
}

/**
 * What a CLI self-update from this dashboard installs: the channel this copy
 * follows, and the exact version the row above offered on it.
 *
 * Read off the report's own CLI row rather than re-derived, so the version in
 * the confirm dialog's command line and the version the install fetches are one
 * field. A dashboard that passed only the channel installed whatever that
 * channel's dist-tag served, which is not the version the page had shown.
 *
 * It is derived SERVER-SIDE on both halves and never carried across the Server
 * Action boundary: an action's parameters arrive as JSON over a POST, so a
 * version taken from the caller would be attacker-supplied text on its way to
 * a child process's argv.
 *
 * No row (a report with no CLI entry at all) answers stable with no version,
 * which is the dist-tag spec that shipped before any of this — never a guess.
 */
export function cliUpdateTarget(report: UpdateReport): CliUpdateTarget {
  const row = report.statuses.find((s) => s.id === 'cli');
  return {
    channel: row?.channel ?? RELEASE_CHANNEL.Stable,
    version: row?.latest ?? null,
  };
}
