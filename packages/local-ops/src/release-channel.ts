import type { DistTags, ReleaseChannel, ReleaseTagSource } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL, RELEASE_TAG_SOURCE } from '@akasecurity/schema';

import { isNewer, prereleaseIdentifiers } from './semver.ts';

// Which release channel a machine follows, and which version it should be
// offered. Pure: no I/O, no child process, no environment read.
//
// The channel is a property of the version a component is RUNNING, derived
// every time. Nothing persists it — a stored channel can disagree with the
// bytes on disk, and a report built from the stored value is then wrong in a
// way nothing on the machine can detect.

/**
 * The channel `version` belongs to, read off its first prerelease identifier.
 *
 * `null`, a release, an unparseable string and a prerelease this vocabulary
 * does not name (`rc`) all answer stable. That is the conservative direction:
 * stable is the channel the `latest` tag serves and the only answer this
 * surface had before channels existed, so an unreadable version can never move
 * a machine onto a prerelease.
 */
export function channelOfVersion(version: string | null): ReleaseChannel {
  if (version === null) return RELEASE_CHANNEL.Stable;
  const [first] = prereleaseIdentifiers(version);
  if (first === RELEASE_CHANNEL.Beta) return RELEASE_CHANNEL.Beta;
  if (first === RELEASE_CHANNEL.Nightly) return RELEASE_CHANNEL.Nightly;
  return RELEASE_CHANNEL.Stable;
}

/** The version to offer on a channel, and which tag it came from. */
export interface ChannelResolution {
  /** The version to offer, or null when no tag served one. */
  version: string | null;
  /** Which dist-tag `version` came from. */
  source: ReleaseTagSource;
}

/**
 * The version to offer a machine on `channel`, given every tag the registry
 * serves for its package, and WHICH TAG that answer came from.
 *
 * The version is the MAX of the channel's own tag and `latest`, never the
 * channel tag alone, and that max is the whole graduation mechanism: `beta`
 * goes on pointing at 0.11.0-beta.3 after 0.11.0 ships, so a reader that took
 * the channel tag by itself would strand a beta machine on a prerelease for
 * ever. A release outranks a prerelease of the same core, so the stable wins
 * exactly when it has caught up.
 *
 * A stable machine reads `latest` and nothing else — the presence of a `beta`
 * tag may not change its answer. A channel nobody has published to falls back
 * to `latest`, because an unpublished channel is not a reason to report
 * nothing. A null map stays null, which is the offline row that nags nobody.
 *
 * The SOURCE is returned beside the version because those last two cases are
 * not the same thing to every caller, and the version alone cannot tell them
 * apart. A machine whose prerelease tag has been retired should be offered the
 * stable — that fallback is the intended answer for the DERIVED path. A channel
 * a user named on the command line should be refused, because the install then
 * asks the registry for a tag nothing publishes. Collapsing the two is what let
 * `--channel nightly` print the stable version as available on a line that has
 * never had a release.
 */
export function resolveChannel(tags: DistTags | null, channel: ReleaseChannel): ChannelResolution {
  if (tags === null) return { version: null, source: RELEASE_TAG_SOURCE.Unknown };
  const stable = tags[DIST_TAG[RELEASE_CHANNEL.Stable]] ?? null;
  if (channel === RELEASE_CHANNEL.Stable) {
    // The stable channel's own tag IS `latest`, so its absence is this package
    // being unpublished rather than a fallback to something else.
    return stable === null
      ? { version: null, source: RELEASE_TAG_SOURCE.Unpublished }
      : { version: stable, source: RELEASE_TAG_SOURCE.Channel };
  }
  const onChannel = tags[DIST_TAG[channel]] ?? null;
  if (onChannel === null) return { version: stable, source: RELEASE_TAG_SOURCE.Unpublished };
  if (stable === null) return { version: onChannel, source: RELEASE_TAG_SOURCE.Channel };
  return isNewer(stable, onChannel)
    ? { version: stable, source: RELEASE_TAG_SOURCE.Graduated }
    : { version: onChannel, source: RELEASE_TAG_SOURCE.Channel };
}

/**
 * The version to offer a machine on `channel` — `resolveChannel`'s version by
 * itself.
 *
 * Kept for the callers that have no channel request to refuse: a plugin's
 * channel is its marketplace registration, so there is no "you asked for a line
 * nothing publishes" case on that path and the fallback is always the answer.
 * A caller acting on the DIFFERENCE between the fallback and a real tag reads
 * `resolveChannel` instead.
 */
export function latestForChannel(tags: DistTags | null, channel: ReleaseChannel): string | null {
  return resolveChannel(tags, channel).version;
}

// Every channel `aka update --channel` accepts, taken from the dist-tag table
// rather than re-listed beside it. A channel this command can ask the registry
// for is exactly a channel that has a tag, and a second hand-written list is
// free to omit a member the table already carries — which is how a documented
// value ends up refused by the parser meant to accept it.
function isSwitchableChannel(raw: string): raw is ReleaseChannel {
  // Its one caller filters Object.keys(DIST_TAG), so every input is already an
  // own key: this narrows the type for the compiler rather than filtering
  // anything at runtime.
  return Object.hasOwn(DIST_TAG, raw);
}

export const SWITCHABLE_CHANNELS: readonly ReleaseChannel[] =
  Object.keys(DIST_TAG).filter(isSwitchableChannel);

/**
 * The channel a raw `--channel` token names, or null.
 *
 * The one place an argv-sourced token becomes a channel. Everything downstream
 * builds an npm spec from the DIST_TAG table, so a token that is not a member
 * has no way to reach a child process's argv — which matters because the
 * shell path on Windows concatenates argv without escaping it.
 */
export function parseSwitchableChannel(raw: string): ReleaseChannel | null {
  return SWITCHABLE_CHANNELS.find((channel) => channel === raw) ?? null;
}
