// Update-status DTOs for the local CLI/plugin update surface. Plain TS
// interfaces (no Zod, no .meta) — these are read-projections of npm + the
// Claude Code plugin ledger, shared by the CLI's update commands and the OSS
// web-ui's Updates page, and deliberately kept out of the generated OpenAPI.

export type ComponentKind = 'cli' | 'plugin';

// The release channels a published version can belong to, spelled the way a
// user types one. A const object rather than a TypeScript `enum`: an enum emits
// runtime code rather than erasing, and this package is reached from a module
// raw Node loads under type stripping.
export const RELEASE_CHANNEL = {
  Stable: 'stable',
  Beta: 'beta',
  Nightly: 'nightly',
} as const;

export type ReleaseChannel = (typeof RELEASE_CHANNEL)[keyof typeof RELEASE_CHANNEL];

// The npm dist-tag each channel is published under.
//
// A SECOND vocabulary joined to the first by member name, and the two cannot be
// collapsed: `stable` is what a user types and `latest` is what the registry
// serves, so one table spelling Stable as `latest` makes `--channel stable`
// unparseable while the undocumented `--channel latest` works. Keyed on
// computed members and annotated `Record<ReleaseChannel, string>`, so a member
// added to RELEASE_CHANNEL fails to compile here until it names its tag.
export const DIST_TAG: Record<ReleaseChannel, string> = {
  [RELEASE_CHANNEL.Stable]: 'latest',
  [RELEASE_CHANNEL.Beta]: 'beta',
  [RELEASE_CHANNEL.Nightly]: 'nightly',
};

// Every dist-tag a registry serves for one package: tag name → version.
//
// The key is an open string rather than a ReleaseChannel, because a registry
// serves whatever tags have been published — including ones this vocabulary
// does not name (`rc`, `next`) — and a reader that typed the key to the
// vocabulary would claim the map only ever carries channels it knows.
export type DistTags = Readonly<Record<string, string>>;

// Which dist-tag a channel's offered version was resolved from.
//
// A const object rather than a boolean, because there are THREE registry states
// a caller acts on differently and a boolean can carry two: a channel that
// serves a tag, a channel that serves none (the offer is the stable fallback,
// which is right for a machine whose prerelease tag was retired and wrong for a
// channel somebody asked for by name), and a lookup that produced no tags at
// all. Folding the middle one into either neighbour is what let `--channel
// nightly` report the stable version as available on a line nothing publishes.
//
// A const object rather than a TypeScript `enum`: an enum emits runtime code
// rather than erasing, and this package is reached from a module raw Node loads
// under type stripping.
export const RELEASE_TAG_SOURCE = {
  /** The channel's own dist-tag served the version. */
  Channel: 'channel',
  /** The stable tag outranked the channel's own — a prerelease that graduated. */
  Graduated: 'graduated',
  /** The channel serves no dist-tag; the version is the stable fallback, or null. */
  Unpublished: 'unpublished',
  /** The lookup produced no tag map at all; the version is null. */
  Unknown: 'unknown',
} as const;

export type ReleaseTagSource = (typeof RELEASE_TAG_SOURCE)[keyof typeof RELEASE_TAG_SOURCE];

// Which published line an update installs, and the exact version resolved on it.
//
// The two travel together because a plan carrying only the channel installed
// whatever that channel's dist-tag happened to serve, which is not the version
// the report offered: `beta` goes on pointing at 0.11.0-beta.3 after 0.11.0
// ships, so a machine told the stable was available re-installed the prerelease
// and was offered the same update for ever.
//
// `version` is REQUIRED and nullable rather than optional. An optional key
// reads as safe at every call site that omits it, and a call site that omitted
// it is the defect itself — so declining is spelled `version: null`, which
// names the choice, and a new surface fails to compile until it makes one.
export interface CliUpdateTarget {
  channel: ReleaseChannel;
  /** The version the report resolved on `channel`, or null when it resolved none. */
  version: string | null;
}

// A row in the update table: what's installed vs. the latest published.
// `installed` is null when the component isn't installed; `latest` is null when
// it couldn't be resolved (offline / no registry auth).
export interface ComponentStatus {
  id: string;
  name: string;
  kind: ComponentKind;
  installed: string | null;
  // The version the host would actually INSTALL, which is not always npm's
  // latest: a plugin resolved through a marketplace manifest that names an
  // exact version can only reach that version. Null when it could not be
  // resolved at all (offline / no registry auth).
  latest: string | null;
  updateAvailable: boolean;
  // Present only when `latest` came from a marketplace pin rather than from
  // npm, which is what lets a surface explain a machine that is current
  // against its own marketplace while npm has moved on. Without it the two
  // cases render identically — "up to date" beside a version the user can see
  // is behind — and the difference is exactly what a reader needs.
  marketplacePin?: MarketplacePin;
  // Which release channel this row's `latest` was resolved against, DERIVED
  // from the installed version each time the report is built rather than stored
  // anywhere: a stored channel can disagree with the bytes on disk, and then
  // every row is wrong in a way nothing can detect.
  //
  // Optional, and an absent value reads as stable — which is what every
  // producer written before channels existed means, and what a machine with
  // nothing installed has opted into.
  channel?: ReleaseChannel;
  // Which dist-tag `latest` above was resolved from, so a caller that asked for
  // a channel BY NAME can refuse a line nothing publishes instead of offering
  // it the stable version it would then fail to fetch.
  //
  // Describes `latest` and nothing else, which is why it is ABSENT on a row
  // whose `latest` came from a marketplace pin rather than from a dist-tag —
  // `marketplacePin` is that row's answer and is already carried beside it. An
  // absent value therefore means "not resolved from a dist-tag", never
  // "resolved from the channel's own".
  latestFrom?: ReleaseTagSource;
  // Present only when `latestFrom` is `graduated`: the version `channel`'s OWN
  // dist-tag was serving before the stable release overtook it. `latest`
  // above is the stable version that won the comparison, so this is the only
  // place the channel's own answer survives — which is what a caller refusing
  // an explicitly requested graduated channel needs to say what that line
  // actually publishes, rather than naming only the stable version that
  // displaced it.
  channelLatest?: string;
  // Present only when an organization's managed settings installed this
  // plugin. `updateAvailable` is then always false, because nothing here may
  // drive that install, and `latest` is the version the organization's
  // marketplace pins, or null when no exact pin could be read. npm's latest
  // is not what decides a managed install, so it is never offered as one.
  managedInstall?: ManagedPluginInstall;
}

// A plugin install an organization's managed settings put in place — the
// host records it at its `managed` scope. The organization's marketplace
// declaration decides the version, and the host's own plugin autoupdate is
// what moves it.
export interface ManagedPluginInstall {
  // The ref (a tag or a branch) the host checked the organization's
  // marketplace out at, when its own record names one.
  ref?: string;
  // Whether `latest` is ahead of `installed`: the organization's pin has moved
  // and the host has not installed it yet. Computed where semver comparison
  // lives, for the same reason as `MarketplacePin.npmAhead`.
  pending: boolean;
}

// How a managed plugin install moves, in the one wording every surface uses:
// the CLI's report and refusals, the apply path's refusal, and the dashboard.
// Spelled once so the surfaces cannot drift into describing different routes.
export const MANAGED_PLUGIN_ADVICE =
  "Your organization's managed settings install it and pin its version. Updates arrive " +
  "through Claude Code's own plugin autoupdate when a new session starts, or /plugin → " +
  'update inside a session.';

// Where a pinned `latest` came from, and what npm said instead.
export interface MarketplacePin {
  // The marketplace whose manifest carries the pin, so the message can name
  // the thing the user would have to move.
  marketplace: string;
  // npm's own latest for the same package, or null when it could not be read.
  // Carried rather than recomputed because a surface that re-derived it would
  // ask the registry a second time to explain one line of output.
  npmLatest: string | null;
  // Whether npm is strictly AHEAD of the pin — the only case worth explaining,
  // since a pin that equals npm explains nothing and the two agree on the happy
  // path. Computed where semver comparison already lives rather than in each
  // renderer: `@akasecurity/dashboard-ui` may not import `local-ops` at all, so
  // a view deriving this would either cross a package wall or carry a second
  // comparator that could disagree with the first. Always false when `range`
  // below is set — a range is not a single version to compare npm against.
  npmAhead: boolean;
  // The manifest's own text when the pin is a semver RANGE (`^2.0.0`) or a
  // dist-tag (`beta`) rather than an exact version — present only then. Those
  // are not values this report can compare against npm's answer, so they are
  // carried as evidence for a note rather than silently read as "no pin",
  // which is what let a row offer npm's own latest as an update the host,
  // resolving within the range, would never actually install.
  range?: string;
}

// An available agent plugin the user has NOT installed yet — surfaced so they
// learn a new integration exists.
export interface AvailablePlugin {
  id: string;
  name: string;
  latest: string | null;
}

export interface UpdateReport {
  statuses: ComponentStatus[];
  availablePlugins: AvailablePlugin[];
}

// The passive-notice cache persisted at ~/.aka/data/update-check.json.
export interface UpdateCache {
  checkedAt: number;
  report: UpdateReport;
  notifiedPluginIds: string[];
}
