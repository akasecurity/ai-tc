// Which channel a machine follows, and which version it should be offered.
//
// Colocated in src/ beside the module, which is where this package's
// install-channel and self-exec suites already live.
//
// Two properties here cannot be seen from the derivation alone and are the
// reason this file exists. A stable machine's answer must not move when a
// prerelease tag appears beside `latest` — with one lookup serving both, the
// two reads are one line apart and it is easy to write a resolution where they
// are the same read. And a beta machine must GRADUATE: the channel tag goes on
// pointing at the prerelease after the release of the same core ships, so
// anything that trusts the channel tag by itself strands that machine for ever
// while reporting it up to date.
import type { DistTags } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL, RELEASE_TAG_SOURCE } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  channelOfVersion,
  latestForChannel,
  parseSwitchableChannel,
  resolveChannel,
  SWITCHABLE_CHANNELS,
} from './release-channel.ts';
import { isNewer } from './semver.ts';

describe('the two vocabularies', () => {
  it('spells a channel as a user types it and its tag separately', () => {
    // Collapsing these is the defect this split exists to prevent: with
    // `Stable` holding the tag name, `--channel stable` is refused by the
    // parser that documents it while the undocumented `--channel latest` works.
    expect(RELEASE_CHANNEL.Stable).toBe('stable');
    expect(DIST_TAG[RELEASE_CHANNEL.Stable]).toBe('latest');
    expect(DIST_TAG[RELEASE_CHANNEL.Stable]).not.toBe(RELEASE_CHANNEL.Stable);
  });

  it('gives every channel a tag', () => {
    expect(Object.values(RELEASE_CHANNEL).length).toBeGreaterThan(0);
    for (const channel of Object.values(RELEASE_CHANNEL)) {
      expect(DIST_TAG[channel], channel).toBeTruthy();
    }
  });
});

describe('channelOfVersion', () => {
  it('reads the first prerelease identifier', () => {
    expect(channelOfVersion('0.11.0-beta.1')).toBe(RELEASE_CHANNEL.Beta);
    expect(channelOfVersion('0.11.0-nightly.20260918.gabc1234')).toBe(RELEASE_CHANNEL.Nightly);
  });

  it('answers stable for everything that names no channel', () => {
    // The conservative-direction control. Widen this to treat any prerelease as
    // beta and the `rc` and unparseable rows flip — which is the whole point:
    // an unreadable version may never move a machine onto a prerelease line.
    expect(channelOfVersion('0.9.11')).toBe(RELEASE_CHANNEL.Stable);
    expect(channelOfVersion('0.11.0-rc.1')).toBe(RELEASE_CHANNEL.Stable);
    expect(channelOfVersion('0.11.0-alpha.1')).toBe(RELEASE_CHANNEL.Stable);
    expect(channelOfVersion('not-a-version')).toBe(RELEASE_CHANNEL.Stable);
    expect(channelOfVersion('')).toBe(RELEASE_CHANNEL.Stable);
    expect(channelOfVersion(null)).toBe(RELEASE_CHANNEL.Stable);
  });

  it('reads the FIRST identifier, not any identifier', () => {
    // `beta` appearing later in a version is not a beta: an rc built from a
    // beta line is on the rc line, and matching anywhere in the identifier list
    // would put that machine on the beta tag.
    expect(channelOfVersion('0.11.0-rc.1.beta')).toBe(RELEASE_CHANNEL.Stable);
  });
});

describe('latestForChannel — a stable machine', () => {
  it('is offered the stable tag', () => {
    expect(latestForChannel({ latest: '0.9.12' }, RELEASE_CHANNEL.Stable)).toBe('0.9.12');
  });

  it('is never offered a prerelease, however new it is', () => {
    expect(
      latestForChannel({ latest: '0.9.12', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Stable),
    ).toBe('0.9.12');
  });

  it('answers identically whether or not a prerelease tag exists', () => {
    // Stated as an EQUALITY between the two registry states, because that is
    // the property: the presence of a beta tag is not an input to a stable
    // machine's answer. A resolution that read both tags for every channel
    // satisfies the case above on its max and fails this one.
    expect(latestForChannel({ latest: '0.9.12' }, RELEASE_CHANNEL.Stable)).toBe(
      latestForChannel({ latest: '0.9.12', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Stable),
    );
  });

  it('is offered nothing when the stable tag is missing', () => {
    expect(latestForChannel({ beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Stable)).toBeNull();
  });
});

describe('latestForChannel — a prerelease machine', () => {
  it('is offered its own channel tag while it leads', () => {
    expect(
      latestForChannel({ latest: '0.9.12', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta),
    ).toBe('0.11.0-beta.3');
  });

  it('graduates onto the stable of the same core the moment it ships', () => {
    expect(
      latestForChannel({ latest: '0.11.0', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta),
    ).toBe('0.11.0');
  });

  it('graduates onto a later stable too, not only the matching core', () => {
    expect(
      latestForChannel({ latest: '0.12.0', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta),
    ).toBe('0.12.0');
  });

  it('falls back to the stable tag when its channel has nothing published', () => {
    expect(latestForChannel({ latest: '0.9.12' }, RELEASE_CHANNEL.Beta)).toBe('0.9.12');
    expect(latestForChannel({ latest: '0.9.12' }, RELEASE_CHANNEL.Nightly)).toBe('0.9.12');
  });

  it('is offered its channel tag when the stable tag is the missing one', () => {
    expect(latestForChannel({ beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta)).toBe('0.11.0-beta.3');
  });

  it('reads the nightly tag for nightly, not the beta tag', () => {
    expect(
      latestForChannel(
        { latest: '0.9.12', beta: '0.11.0-beta.3', nightly: '0.9.13-nightly.20260918.gabc1234' },
        RELEASE_CHANNEL.Nightly,
      ),
    ).toBe('0.9.13-nightly.20260918.gabc1234');
  });

  it('answers nothing at all when the lookup produced no map', () => {
    // The offline row: a failed registry read stays `unknown`, and must not
    // become a nag on any channel.
    for (const channel of Object.values(RELEASE_CHANNEL)) {
      expect(latestForChannel(null, channel), channel).toBeNull();
    }
  });

  it('ignores a tag nothing asked for', () => {
    // A registry serves whatever has been published, including lines this
    // vocabulary does not name. An `rc` tag must reach nobody's answer.
    expect(latestForChannel({ latest: '0.9.12', rc: '2.0.0-rc.1' }, RELEASE_CHANNEL.Beta)).toBe(
      '0.9.12',
    );
  });
});

// The ordering the graduation rests on, driven on the SAME core — which is the
// only input that reaches the prerelease comparison at all. A pair with
// differing cores is decided on the core loop and says nothing about this.
describe('the ordering graduation depends on', () => {
  it('ranks a release above a prerelease of the same core', () => {
    expect(isNewer('0.11.0', '0.11.0-beta.2')).toBe(true);
    expect(isNewer('0.11.0-beta.3', '0.11.0')).toBe(false);
  });

  it('orders two prereleases on the same core by their identifiers', () => {
    expect(isNewer('0.11.0-beta.3', '0.11.0-beta.2')).toBe(true);
    expect(isNewer('0.9.13-nightly.20260919.gdef5678', '0.9.13-nightly.20260918.gabc1234')).toBe(
      true,
    );
  });

  it('puts a nightly above the release it was stamped from and below its own core', () => {
    // Why a nightly is stamped from the NEXT patch: stamped from the manifest
    // version it would sort BELOW the stable it was built after, and a nightly
    // machine would be offered the older release it is already ahead of.
    expect(isNewer('0.9.12-nightly.20260918.gabc1234', '0.9.11')).toBe(true);
    expect(isNewer('0.9.12', '0.9.12-nightly.20260918.gabc1234')).toBe(true);
  });
});

describe('parseSwitchableChannel', () => {
  it('accepts every channel the dist-tag table names', () => {
    expect(SWITCHABLE_CHANNELS.length).toBeGreaterThan(0);
    for (const channel of Object.values(RELEASE_CHANNEL)) {
      expect(parseSwitchableChannel(channel), channel).toBe(channel);
    }
  });

  it('accepts the token the flag documents', () => {
    // Spelled as a literal on purpose, because this is the case the two-table
    // split exists for: it is what a user types, and it has to survive however
    // the members are renamed.
    expect(parseSwitchableChannel('stable')).toBe(RELEASE_CHANNEL.Stable);
    expect(parseSwitchableChannel('beta')).toBe(RELEASE_CHANNEL.Beta);
  });

  it('refuses a dist-tag name, which is not a channel a user types', () => {
    expect(parseSwitchableChannel('latest')).toBeNull();
  });

  it('refuses anything that is not a member', () => {
    for (const raw of ['', 'bogus', 'rc', 'STABLE', 'Beta', ' beta', 'beta ']) {
      expect(parseSwitchableChannel(raw), raw).toBeNull();
    }
  });

  it('refuses a token carrying shell metacharacters', () => {
    // The refusal that keeps an argv-sourced token out of a child process:
    // `local-ops`' shelled spawn concatenates argv without escaping it on
    // Windows, so the parse — not the spawn — is where a hostile value stops.
    for (const raw of [
      'beta; rm -rf /',
      'beta && curl http://example.test',
      'beta | tee /tmp/x',
      'beta`whoami`',
      'beta$(whoami)',
      'beta\nstable',
      'beta%PATH%',
    ]) {
      expect(parseSwitchableChannel(raw), raw).toBeNull();
    }
  });

  it('refuses a key reached through the prototype rather than the table', () => {
    for (const raw of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(parseSwitchableChannel(raw), raw).toBeNull();
    }
  });
});

/**
 * WHICH TAG the offer came from, which the version alone cannot say.
 *
 * Two registry states produce the same version and call for opposite answers: a
 * machine whose own prerelease tag has been retired should be offered the
 * stable, and a channel a user named on the command line should be refused,
 * because the install would then ask the registry for a tag nothing publishes.
 * Collapsing them into `latest` is what let `--channel nightly` print the
 * stable version as available on a line that has never had a release.
 */
describe('resolveChannel — where the answer came from', () => {
  it('reports the channel’s own tag when that tag decided', () => {
    expect(
      resolveChannel({ latest: '0.9.12', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta),
    ).toStrictEqual({ version: '0.11.0-beta.3', source: RELEASE_TAG_SOURCE.Channel });
  });

  it('reports a graduation when the stable outranked the channel’s tag', () => {
    expect(
      resolveChannel({ latest: '0.11.0', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta),
    ).toStrictEqual({ version: '0.11.0', source: RELEASE_TAG_SOURCE.Graduated });
  });

  it('does NOT report a graduation where the two tags serve the same version', () => {
    // The boundary between the two members above, and a real registry state:
    // publishing a release to `latest` and to `beta` together leaves both
    // pointing at one version. The channel's own tag did serve what is offered,
    // so `Graduated` — "the stable OUTRANKED it" — would be a false claim about
    // the same string. The versions being equal is exactly why the source is
    // the only thing that can be wrong here, and why a strict comparison and a
    // negated reversed one look identical everywhere else.
    expect(
      resolveChannel({ latest: '0.11.0', beta: '0.11.0' }, RELEASE_CHANNEL.Beta),
    ).toStrictEqual({ version: '0.11.0', source: RELEASE_TAG_SOURCE.Channel });
  });

  it('keeps the channel’s tag when neither version can be ordered', () => {
    // A registry may serve anything on a tag. Neither side is orderable, so
    // nothing outranks anything, and the channel asked for is what answers.
    expect(
      resolveChannel({ latest: 'not-a-version', beta: 'also-not' }, RELEASE_CHANNEL.Beta),
    ).toStrictEqual({ version: 'also-not', source: RELEASE_TAG_SOURCE.Channel });
    // And an unorderable stable beside an orderable channel tag: the stable
    // cannot be shown to be ahead, so it does not displace the channel's.
    expect(
      resolveChannel({ latest: 'not-a-version', beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Beta),
    ).toStrictEqual({ version: '0.11.0-beta.3', source: RELEASE_TAG_SOURCE.Channel });
  });

  it('reports UNPUBLISHED, with the fallback version, when the channel serves no tag', () => {
    // Both halves matter and they are why this is not a boolean: the version is
    // still the right OFFER for a derived read, and the source is the only
    // thing that lets an explicit request be refused.
    for (const channel of [RELEASE_CHANNEL.Beta, RELEASE_CHANNEL.Nightly]) {
      expect(resolveChannel({ latest: '0.9.12' }, channel), channel).toStrictEqual({
        version: '0.9.12',
        source: RELEASE_TAG_SOURCE.Unpublished,
      });
    }
  });

  it('distinguishes an unpublished channel from an unreachable registry', () => {
    // The third state a boolean cannot carry. One is "nothing has been released
    // there", the other is "we do not know" — and only the first is a refusal.
    const unpublished = resolveChannel({ latest: '0.9.12' }, RELEASE_CHANNEL.Nightly);
    const unreachable = resolveChannel(null, RELEASE_CHANNEL.Nightly);
    expect(unpublished.source).toBe(RELEASE_TAG_SOURCE.Unpublished);
    expect(unreachable.source).toBe(RELEASE_TAG_SOURCE.Unknown);
    expect(unpublished.source).not.toBe(unreachable.source);
    expect(unreachable.version).toBeNull();
  });

  it('reads a missing stable tag as the stable channel being unpublished', () => {
    expect(resolveChannel({ beta: '0.11.0-beta.3' }, RELEASE_CHANNEL.Stable)).toStrictEqual({
      version: null,
      source: RELEASE_TAG_SOURCE.Unpublished,
    });
  });

  it('never reports a source outside the vocabulary', () => {
    const sources = Object.values(RELEASE_TAG_SOURCE);
    expect(sources.length).toBeGreaterThan(0);
    const maps: (DistTags | null)[] = [
      null,
      {},
      { latest: '0.9.12' },
      { beta: '0.11.0-beta.3' },
      { latest: '0.11.0', beta: '0.11.0-beta.3' },
      { latest: '0.9.12', nightly: '0.9.13-nightly.20260918.gabc1234' },
      { rc: '2.0.0-rc.1' },
    ];
    for (const tags of maps) {
      for (const channel of Object.values(RELEASE_CHANNEL)) {
        expect(sources, `${JSON.stringify(tags)} ${channel}`).toContain(
          resolveChannel(tags, channel).source,
        );
      }
    }
  });

  it('agrees with latestForChannel on every version it reports', () => {
    // The projection is the whole of the older reader, so a resolution that
    // moved a version would move both — and every existing caller with it.
    const maps: (DistTags | null)[] = [
      null,
      { latest: '0.9.12' },
      { latest: '0.9.12', beta: '0.11.0-beta.3' },
      { latest: '0.11.0', beta: '0.11.0-beta.3' },
      { beta: '0.11.0-beta.3' },
      { latest: '0.9.12', rc: '2.0.0-rc.1' },
    ];
    for (const tags of maps) {
      for (const channel of Object.values(RELEASE_CHANNEL)) {
        expect(latestForChannel(tags, channel), `${JSON.stringify(tags)} ${channel}`).toBe(
          resolveChannel(tags, channel).version,
        );
      }
    }
  });
});
