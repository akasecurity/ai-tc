import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
  AvailablePlugin,
  ComponentStatus,
  DistTags,
  ReleaseChannel,
  UpdateReport,
} from '@akasecurity/schema';
import { DIST_TAG, RELEASE_TAG_SOURCE } from '@akasecurity/schema';

import type { RunResult } from './exec.ts';
import { runCapture } from './exec.ts';
import type { MarketplacePinLookup } from './marketplace-manifest.ts';
import { marketplacePinnedVersion, marketplaceSourceRef } from './marketplace-manifest.ts';
import { AGENT_PLUGINS, type AgentPlugin, pluginRef } from './registry.ts';
import { channelOfVersion, resolveChannel } from './release-channel.ts';
import { compareSemver, isNewer, isSemver } from './semver.ts';

// Pure update-report gathering: version discovery over npm + the local Claude Code
// ledger, with no @akasecurity/plugin-sdk dependency (so the report logic stays unit-
// testable without dragging in the env-reading config layer). Cache + passive-notice
// persistence lives in ./update-cache.ts. The report DTOs live in
// @akasecurity/schema (zod/updates.ts), shared with the web-ui's Updates page.

// The npm package the global `aka` CLI is published as. `npm view` resolves its
// latest version through the user's own npm configuration — the same toolchain
// that installed it.
export const CLI_PACKAGE = '@akasecurity/cli';

// Injectable seams so gatherReport is testable without touching the network or the
// real ~/.claude ledger.
export interface ReportDeps {
  // Every dist-tag the registry serves for one package, or null when the
  // lookup produced no usable answer.
  //
  // The whole MAP rather than a single version, because each component's
  // channel is derived separately and the version for one channel cannot be
  // re-derived from the version for another. One map is still ONE registry
  // request per package, which is what keeps the disclosed lookup count true.
  //
  // RENAMED rather than widened in place: the seam's old name described a
  // single version, and a widened seam under the old name leaves every call
  // site compiling while one of them goes on handing back the wrong shape.
  viewDistTags: (pkg: string) => DistTags | null;
  installed: Map<string, string>;
  cliInstalled: string | null;
  // What the HOST would install for this agent, from the marketplace manifest
  // it resolved — `{ version: null }` when no pin applies and npm's latest is
  // the right answer. See marketplace-manifest.ts for why the two can differ,
  // and for why a RANGE or dist-tag pin is carried as `range` evidence rather
  // than collapsed into "no pin" — the row still must not offer npm's latest
  // as an update the host cannot resolve to.
  //
  // REQUIRED, not optional. An optional seam reads as safe at every call site
  // that omits it, which is every call site until somebody remembers — and the
  // one that omitted it would go back to reporting an update the host cannot
  // deliver, silently. Required, the compiler names each caller that has to
  // decide; a caller with no marketplace to read says so with
  // `() => ({ version: null })`.
  marketplacePin: (agent: AgentPlugin) => MarketplacePinLookup;
  // The install an organization's managed settings put in place for this
  // agent, or null when there is none. Such a row is reported and never
  // offered as an update: the organization's pin decides its version and the
  // host's own autoupdate moves it.
  //
  // REQUIRED for the same reason `marketplacePin` is. The caller that omitted
  // it would go back to offering `aka update` an install it must not drive, and
  // nothing would say so. A caller with no ledger to read says `() => null`.
  managedInstall: (agent: AgentPlugin) => ManagedInstallLookup | null;
  // The channel to resolve the CLI row against, when a caller is asking to move
  // this copy onto another published line rather than to follow the one it is
  // on. Absent means derive it, which is what every read-only surface wants.
  //
  // It exists because `updateAvailable` is what decides whether anything is
  // applied at all: a machine current on stable has no row to act on, so a
  // report resolved against the channel it is ALREADY on answers a request to
  // switch with "everything is up to date" and changes nothing.
  //
  // It does NOT by itself make the printed version equal the fetched one: the
  // row's own `latest` is what the install builds its spec from, and a caller
  // that resolved a row here and then installed a dist-tag would print one
  // version and fetch another.
  //
  // CLI-only, because only the CLI's channel is switchable here: a plugin's is
  // its marketplace registration, which this process cannot change.
  // Spelled `| undefined` so a caller that has no flag to pass can say so —
  // `gatherReportLive`'s own optional parameter arrives here as `undefined`,
  // and under `exactOptionalPropertyTypes` that is a different thing from the
  // key being absent.
  cliChannel?: ReleaseChannel | undefined;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// Read the CLI's own version from the nearest package.json named `@akasecurity/cli`,
// walking up from `fromDir` (default: this module's directory). Works bundled
// (dist/cli.js → package root), under tsx in dev (src/lib → cli), and from
// the web-ui's standalone server (which passes its cwd — nested inside the
// published CLI package at <cli-pkg>/web-ui/web-ui). Returns null if not
// found — callers treat an unknown installed version the same as an unknown
// latest: never flag an update (a `0.0.0` fallback would be "older" than every
// real release and nag forever).
export function cliVersion(fromDir?: string): string | null {
  let dir = fromDir ?? dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(dir, 'package.json');
    if (existsSync(p)) {
      try {
        const raw: unknown = JSON.parse(readFileSync(p, 'utf8'));
        if (isRecord(raw) && raw.name === CLI_PACKAGE && typeof raw.version === 'string') {
          return raw.version;
        }
      } catch {
        // unreadable/!JSON — keep walking up
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

// The `recorded_by` stamp for available_packs mirror writes — which binary
// recorded the detection inventory (`aka-cli@<version>`). Undefined when the
// CLI's own version is unknowable (a dev checkout): better absent than a
// lying constant.
export function cliRecordedBy(): { recordedBy: string } | undefined {
  const version = cliVersion();
  return version === null ? undefined : { recordedBy: `aka-cli@${version}` };
}

// Default location of Claude Code's plugin install ledger.
function installedPluginsPath(claudeHome: string): string {
  return join(claudeHome, 'plugins', 'installed_plugins.json');
}

/** One installed record, as the two readers below project it. */
export interface InstalledPlugin {
  version: string;
  // The scope the version above was read from, when the ledger names one. It
  // is what an update has to target: the reader below falls back past `user`,
  // so the record a comparison used is not necessarily the one a host CLI
  // would pick on its own.
  scope?: string;
}

// Parse ~/.claude/plugins/installed_plugins.json (v2) into a map of
// `<plugin>@<marketplace>` → the record the comparison should use. Missing or
// garbage file → empty map.
//
// The SCOPE is carried beside the version rather than dropped, and that is the
// whole point of this shape: the fallback below reads a record at any scope,
// while `claude plugin update` defaults to `user`. Returning only the version
// made the two halves talk about different installs with nothing to reconcile
// them, so a plugin an enterprise drop-in had put at `managed` was reported
// out of date and could never be updated.
export function installedPlugins(
  claudeHome: string = join(homedir(), '.claude'),
): Map<string, InstalledPlugin> {
  const out = new Map<string, InstalledPlugin>();
  for (const [ref, records] of ledgerRecords(claudeHome)) {
    // Prefer a `user`-scope record; fall back to the first with a version string.
    const record =
      records.find((r): r is Record<string, unknown> => isRecord(r) && r.scope === 'user') ??
      records.find((r): r is Record<string, unknown> => isRecord(r));
    if (record && typeof record.version === 'string') {
      out.set(ref, {
        version: record.version,
        ...(typeof record.scope === 'string' ? { scope: record.scope } : {}),
      });
    }
  }
  return out;
}

// Every non-empty record list the ledger holds, keyed by ref, before any
// record is chosen. Missing or garbage file → empty map.
function ledgerRecords(claudeHome: string): Map<string, unknown[]> {
  const out = new Map<string, unknown[]>();
  const path = installedPluginsPath(claudeHome);
  if (!existsSync(path)) return out;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return out;
  }
  if (!isRecord(raw) || !isRecord(raw.plugins)) return out;
  for (const [ref, records] of Object.entries(raw.plugins)) {
    if (Array.isArray(records) && records.length > 0) out.set(ref, records);
  }
  return out;
}

/** The scope a ref is installed at, or undefined when the ledger names none. */
export function installedPluginScope(ref: string, claudeHome?: string): string | undefined {
  return installedPlugins(claudeHome).get(ref)?.scope;
}

// The scope Claude Code records a plugin at when an organization's managed
// settings force-enable it.
const MANAGED_SCOPE = 'managed';

/** What a managed install is running, and where the host resolved it from. */
export interface ManagedInstallLookup {
  // The version the managed-scope record carries.
  version: string;
  // The ref the organization's marketplace is checked out at, when the host's
  // record of that marketplace names one.
  ref?: string;
}

/**
 * The install an organization's managed settings put in place for an agent's
 * plugin, or null when there is none.
 *
 * Its own reader rather than a flag on `installedPlugins`, because the two
 * answer different questions about the same ledger. The comparison reader
 * prefers a `user` record and every non-managed install depends on that
 * choice staying as it is. This one asks whether ANY record is `managed`.
 * The host resolves the managed copy when a user copy sits beside it
 * (`claude plugin details` reports the managed record's version), so one
 * managed record makes the plugin the organization's, whatever else the
 * ledger lists.
 *
 * The host check is the same one `marketplacePinnedVersion` makes, for the
 * same reason: every registered agent with a ref could be looked up in this
 * ledger, but only a Claude Code agent's answer means anything there.
 */
export function managedPluginInstall(
  agent: AgentPlugin,
  claudeHome: string = join(homedir(), '.claude'),
): ManagedInstallLookup | null {
  if (agent.cliBin !== 'claude') return null;
  const ref = pluginRef(agent);
  if (ref === undefined) return null;
  const record = ledgerRecords(claudeHome)
    .get(ref)
    ?.find((r): r is Record<string, unknown> => isRecord(r) && r.scope === MANAGED_SCOPE);
  if (record === undefined || typeof record.version !== 'string') return null;
  const sourceRef =
    agent.marketplace === undefined
      ? undefined
      : marketplaceSourceRef(claudeHome, agent.marketplace);
  return { version: record.version, ...(sourceRef !== undefined ? { ref: sourceRef } : {}) };
}

// The version-only projection every version comparison takes.
export function installedPluginVersions(claudeHome?: string): Map<string, string> {
  return new Map([...installedPlugins(claudeHome)].map(([ref, { version }]) => [ref, version]));
}

// Codex CLI caches an installed plugin's contents under
// `<codexHome>/plugins/cache/<marketplaceName>/<pluginName>/<version>/`, with
// possibly more than one version directory present (a stale prior install
// left behind) — there is no single ledger file to parse the way Claude
// Code's installed_plugins.json is, so this walks the cache directory instead.
// Confirmed against openai/codex's own `PluginStore::active_plugin_version`
// (codex-rs/core-plugins/src/store.rs): the "active" version is the
// highest-semver subdirectory found, UNLESS a literal `local` version
// directory exists (a dev-mode install marker), which always wins.
function codexPluginCacheRoot(codexHome: string): string {
  return join(codexHome, 'plugins', 'cache');
}

function activeCodexPluginVersion(dir: string): string | null {
  let entries: string[];
  try {
    entries = readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
  } catch {
    return null;
  }
  if (entries.length === 0) return null;
  if (entries.includes('local')) return 'local';
  // Only orderable names may enter the reduce. compareSemver returns 0 for
  // input it cannot parse, so a stray sibling (a partial download, an editor
  // scratch dir) that reaches the accumulator can never be displaced: it would
  // be reported as the installed version, and isNewer(latest, junk) is 0 too,
  // so the update silently stops being offered.
  const versions = entries.filter(isSemver);
  if (versions.length === 0) return null;
  return versions.reduce((best, candidate) =>
    compareSemver(candidate, best) > 0 ? candidate : best,
  );
}

// Walk `<codexHome>/plugins/cache/<marketplace>/<pluginName>/` for every
// codex-`cliBin` agent in the registry and resolve its active installed
// version, keyed the same way as installedPluginVersions() (`<plugin>@
// <marketplace>`) so the two maps merge directly — see
// installedAgentPluginVersions() below.
export function installedCodexPluginVersions(
  codexHome: string = join(homedir(), '.codex'),
): Map<string, string> {
  const out = new Map<string, string>();
  const cacheRoot = codexPluginCacheRoot(codexHome);
  for (const agent of AGENT_PLUGINS) {
    if (agent.cliBin !== 'codex') continue;
    const ref = pluginRef(agent);
    if (!ref || !agent.pluginName || !agent.marketplace) continue;
    const pluginDir = join(cacheRoot, agent.marketplace, agent.pluginName);
    const version = activeCodexPluginVersion(pluginDir);
    if (version !== null) out.set(ref, version);
  }
  return out;
}

// The merged view `gatherReport`'s `installed` map needs: every registered
// agent's installed version, regardless of which host CLI's ledger/cache
// format it comes from. Refs never collide across agents (registry.ts keeps
// each agent's `pluginName` distinct for exactly this reason), so a plain
// merge is safe — no agent's entry can shadow another's.
export function installedAgentPluginVersions(
  claudeHome?: string,
  codexHome?: string,
): Map<string, string> {
  return new Map([
    ...installedPluginVersions(claudeHome),
    ...installedCodexPluginVersions(codexHome),
  ]);
}

/**
 * `npm view <pkg> dist-tags --json` — every tag the registry serves for a
 * package, or null on any failure.
 *
 * ONE request, asking for the whole tag map rather than for one channel's
 * version: a second read per package would double what the registry is told
 * this machine is interested in, and the disclosure counts those requests.
 *
 * `--json` is load-bearing. The human-readable form of `npm view <pkg>
 * dist-tags` is sorted and truncated, so the plain form can omit the very tag
 * being asked for.
 *
 * Anything that is not an object of string→string reads as NO ANSWER rather
 * than as a partial one: a non-string version would be handed to the semver
 * comparator, which treats what it cannot parse as equal, so a junk value
 * silently stops an update being offered instead of failing visibly.
 *
 * `capture` is a seam so this can be driven without a spawn. The PATH shims in
 * this repo fail OPEN, so an unstubbed probe reaches the developer's own npm
 * and the real registry.
 */
/**
 * The first line-leading `{` in `stdout` whose remaining text parses as a
 * plain JSON object — trying each candidate IN ORDER rather than stopping at
 * the first `{` anywhere in the buffer.
 *
 * npm may put a warning line on stdout ahead of the payload, and that line can
 * itself carry a brace of its own (quoting a config value or a flag) —
 * `npm warn using --force Recommended protections disabled. {config}`. A
 * byte-scan for the first `{` lands inside that warning and fails the whole
 * read on what is a cosmetic line, which is a narrower defence than the
 * last-line read this replaced. Restricting a candidate to where a LINE begins
 * (optional leading whitespace, then `{`) is what skips the warning without
 * needing to recognise it: nothing before it on that line is whitespace, so it
 * is never a candidate at all.
 */
function firstJsonObjectFromLines(stdout: string): Record<string, unknown> | null {
  let offset = 0;
  for (const line of stdout.split('\n')) {
    const indent = /^[ \t]*/.exec(line)?.[0].length ?? 0;
    if (line[indent] === '{') {
      try {
        const parsed: unknown = JSON.parse(stdout.slice(offset + indent));
        // A successful parse from a line-leading `{` is a plain object by the
        // JSON grammar — this narrows `unknown` rather than screening a shape
        // that could arrive. An array or a scalar cannot start with `{`.
        if (isRecord(parsed)) return parsed;
      } catch {
        // Not valid JSON starting here — a warning line's own brace, or a
        // payload that continues past what looked like its close. Try the
        // next line-leading `{`.
      }
    }
    offset += line.length + 1; // +1 for the '\n' the split consumed.
  }
  return null;
}

export function npmViewDistTags(
  pkg: string,
  capture: (command: string, args: string[], timeoutMs?: number) => RunResult = runCapture,
): DistTags | null {
  const res = capture('npm', ['view', pkg, 'dist-tags', '--json'], 15_000);
  if (!res.ok || !res.stdout) return null;
  const raw = firstJsonObjectFromLines(res.stdout);
  if (raw === null) return null;
  const tags: Record<string, string> = {};
  for (const [tag, version] of Object.entries(raw)) {
    if (typeof version !== 'string') return null;
    tags[tag] = version;
  }
  return tags;
}

// Build the full update report: the CLI plus every marketplace agent, split into
// installed (with an installed-vs-latest status) and available-but-not-installed.
export function gatherReport(deps: ReportDeps): UpdateReport {
  // The channel is derived PER COMPONENT, from that component's own installed
  // version. One channel for the whole report would resolve a beta plugin
  // against the CLI's stable channel and report it as current at a version it
  // is already ahead of.
  //
  // It is derived BEFORE the registry read so the answer can be resolved
  // against it, and it never gates that read: every package is looked up
  // whether or not it is installed, which is exactly what the egress
  // disclosure says happens.
  //
  // An explicit `cliChannel` is the one override, and only for the CLI: a
  // caller switching channels is asking about a line this copy is not on, so
  // deriving there would resolve the row against the channel being left.
  const cliChannel = deps.cliChannel ?? channelOfVersion(deps.cliInstalled);
  // The full resolution rather than its version alone: the CLI is the one
  // component whose channel a caller can ask for BY NAME, and a channel that
  // serves no tag has to be refusable there rather than offered the stable
  // version it would then fail to fetch. Carried onto the row so the refusal
  // costs no second registry request.
  const cliTags = deps.viewDistTags(CLI_PACKAGE);
  const cli = resolveChannel(cliTags, cliChannel);
  const cliLatest = cli.version;
  // Read from the SAME tag map `resolveChannel` was just given, so this costs
  // no second registry request. Only meaningful for `Graduated`, the one
  // source where the channel's own tag and `latest` (the stable winner) are
  // two different versions — and only carried onto the row when it resolved
  // to a real string, since `exactOptionalPropertyTypes` refuses an explicit
  // `undefined` on an optional field.
  const channelLatest =
    cli.source === RELEASE_TAG_SOURCE.Graduated ? cliTags?.[DIST_TAG[cliChannel]] : undefined;
  const statuses: ComponentStatus[] = [
    {
      id: 'cli',
      name: 'aka CLI',
      kind: 'cli',
      installed: deps.cliInstalled,
      latest: cliLatest,
      updateAvailable:
        deps.cliInstalled !== null && cliLatest !== null && isNewer(cliLatest, deps.cliInstalled),
      channel: cliChannel,
      latestFrom: cli.source,
      ...(channelLatest !== undefined ? { channelLatest } : {}),
    },
  ];
  const availablePlugins: AvailablePlugin[] = [];

  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    if (!ref || !agent.npmPackage) continue;
    // A managed install's version is the managed record's, even where a user
    // copy sits beside it: that is the copy the host resolves.
    const managed = deps.managedInstall(agent);
    // A plugin nobody has installed resolves stable: a machine with nothing
    // installed has opted into nothing, and advertising it a prerelease would
    // be this report choosing a channel on the user's behalf.
    const installed = managed?.version ?? deps.installed.get(ref) ?? null;
    const channel = channelOfVersion(installed);
    const npm = resolveChannel(deps.viewDistTags(agent.npmPackage), channel);
    const npmLatest = npm.version;
    // The pin WINS where there is one, because it is what the host resolves an
    // install through. npm's answer is kept beside it rather than discarded:
    // it is the only thing that can explain a machine reading "up to date" at a
    // version the user can see is behind.
    const pin = deps.marketplacePin(agent);
    const latest = pin.version ?? npmLatest;
    // A RANGE pin (or a dist-tag) is not a version this report can compare, so
    // the row must not offer npm's answer as an update the host cannot resolve
    // to — that is exactly the failure a range collapsing into "no pin" used to
    // produce. `latest` above still reads npm's answer for the "Latest" column
    // (informational — the pin's own note is what explains it), but
    // `updateAvailable` is forced false rather than computed from it.
    const rangePinned = pin.version === null && pin.range !== undefined;
    const pinned =
      (pin.version !== null || pin.range !== undefined) && agent.marketplace !== undefined
        ? {
            marketplacePin: {
              marketplace: agent.marketplace,
              npmLatest,
              npmAhead:
                pin.version !== null && npmLatest !== null && isNewer(npmLatest, pin.version),
              ...(pin.range !== undefined ? { range: pin.range } : {}),
            },
          }
        : {};
    if (installed === null) {
      availablePlugins.push({ id: agent.id, name: agent.name, latest });
      continue;
    }
    if (managed !== null) {
      // The organization's EXACT pin is the only target this report can name.
      // npm's answer (and a range, which is not one version) is not what
      // decides a managed install, so either leaves the target unknown rather
      // than offering npm's latest in its place. `latestFrom` is absent because
      // `latest` never comes from a dist-tag here.
      statuses.push({
        id: agent.id,
        name: agent.name,
        kind: 'plugin',
        installed,
        latest: pin.version,
        updateAvailable: false,
        channel,
        ...pinned,
        managedInstall: {
          ...(managed.ref !== undefined ? { ref: managed.ref } : {}),
          pending: pin.version !== null && isNewer(pin.version, installed),
        },
      });
      continue;
    }
    statuses.push({
      id: agent.id,
      name: agent.name,
      kind: 'plugin',
      installed,
      latest,
      updateAvailable: rangePinned ? false : latest !== null && isNewer(latest, installed),
      channel,
      // Set only where `latest` really is the dist-tag resolution. A pin wins
      // over npm's answer, and a field that went on describing the resolution
      // the pin displaced would describe a version this row does not carry —
      // which is true of a RANGE pin exactly as of an exact one, since `latest`
      // above reads npm's answer only because there is no comparable version to
      // prefer over it.
      ...(pin.version === null ? { latestFrom: npm.source } : {}),
      ...pinned,
    });
  }
  return { statuses, availablePlugins };
}

// Convenience wrapper that wires the real network + filesystem seams. Used by the
// user-facing `check-updates`/`update` commands and the background refresh.
//
// `cliChannel` is passed only by a caller asking to move this copy onto another
// published line; every read-only surface omits it and gets the derived answer.
export function gatherReportLive(cliChannel?: ReleaseChannel): UpdateReport {
  return gatherReport({
    viewDistTags: npmViewDistTags,
    installed: installedAgentPluginVersions(),
    cliInstalled: cliVersion(),
    cliChannel,
    // No coordinate guard here: `marketplacePinnedVersion` owns both that and
    // the HOST check, because a guard written at the call site admits Codex —
    // its registry entry carries a marketplace and a plugin name like any
    // other — into a reader that only understands Claude Code's layout.
    marketplacePin: (agent) => marketplacePinnedVersion(agent),
    managedInstall: (agent) => managedPluginInstall(agent),
  });
}
