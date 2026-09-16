import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
  DestinationKind,
  EgressEcosystem,
  ProviderRegistryEntry,
  ShareTrustLevel,
} from '@akasecurity/schema';
import { DATA_CLASS_ORDER } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  EGRESS_VERSION_MATERIAL,
  EXCLUDED_HOST_SUFFIXES,
  isNonDataHost,
  matchMostSpecificEntry,
  NON_DATA_HOST_SUFFIXES,
  PROVIDER_REGISTRY,
  resolveHost,
  resolveSdk,
} from '../../src/egress/registry.ts';

const fixturesDir = join(fileURLToPath(new URL('.', import.meta.url)), '../../src/egress/fixtures');

interface HostCase {
  label: string;
  host: string;
  opts?: { internalDomains?: string[] };
  expect: { kind: DestinationKind; trust: ShareTrustLevel; name: string; category: string } | null;
  /** Checked only when present, against `resolveHost(...)?.providerId`. */
  expectProviderId?: string | null;
}

interface SdkCase {
  label: string;
  ecosystem: EgressEcosystem;
  pkg: string;
  expectId: string | null;
}

interface RegistryFixture {
  hosts: HostCase[];
  sdks: SdkCase[];
}

function loadFixture(): RegistryFixture {
  return JSON.parse(
    readFileSync(join(fixturesDir, 'registry-resolution.json'), 'utf8'),
  ) as RegistryFixture;
}

const fixture = loadFixture();

describe('resolveHost — fixture corpus', () => {
  it('has at least 2 resolved and 2 excluded (null) host cases', () => {
    expect(fixture.hosts.filter((c) => c.expect !== null).length).toBeGreaterThanOrEqual(2);
    expect(fixture.hosts.filter((c) => c.expect === null).length).toBeGreaterThanOrEqual(2);
  });

  it.each(fixture.hosts.map((c) => [c.label, c] as const))('%s', (_label, c) => {
    const result = resolveHost(c.host, c.opts);
    if (c.expect === null) {
      expect(result).toBeNull();
    } else {
      expect(result).not.toBeNull();
      expect(result?.kind).toBe(c.expect.kind);
      expect(result?.trust).toBe(c.expect.trust);
      expect(result?.name).toBe(c.expect.name);
      expect(result?.category).toBe(c.expect.category);
      if (c.expectProviderId !== undefined) {
        expect(result?.providerId).toBe(c.expectProviderId);
      }
    }
  });

  it('has at least one host case pinning a populated providerId and one pinning null', () => {
    const withProviderId = fixture.hosts.filter(
      (c) => c.expect !== null && c.expectProviderId !== undefined,
    );
    expect(withProviderId.some((c) => c.expectProviderId !== null)).toBe(true);
    expect(withProviderId.some((c) => c.expectProviderId === null)).toBe(true);
  });

  it('providers carry the matched registry entry; non-providers carry null', () => {
    const stripe = resolveHost('api.stripe.com');
    expect(stripe?.entry?.id).toBe('stripe');
    const external = resolveHost('acme-partner.com');
    expect(external?.entry).toBeNull();
  });
});

describe('resolveSdk — fixture corpus', () => {
  it('has at least 2 hit and 2 miss sdk cases', () => {
    expect(fixture.sdks.filter((c) => c.expectId !== null).length).toBeGreaterThanOrEqual(2);
    expect(fixture.sdks.filter((c) => c.expectId === null).length).toBeGreaterThanOrEqual(2);
  });

  it.each(fixture.sdks.map((c) => [c.label, c] as const))('%s', (_label, c) => {
    const result = resolveSdk(c.ecosystem, c.pkg);
    if (c.expectId === null) {
      expect(result).toBeNull();
    } else {
      expect(result?.id).toBe(c.expectId);
    }
  });
});

describe('PROVIDER_REGISTRY', () => {
  it('has no duplicate ids', () => {
    const ids = PROVIDER_REGISTRY.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('has 36 seeded providers, each with at least one hostSuffix and one dataClass', () => {
    expect(PROVIDER_REGISTRY.length).toBe(36);
    for (const p of PROVIDER_REGISTRY) {
      expect(p.hostSuffixes.length).toBeGreaterThanOrEqual(1);
      expect(p.defaultDataClasses.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('lists every defaultDataClasses array most-sensitive first', () => {
    // resolveEgress stores defaultDataClasses[0] as the endpoint's dataClass, so
    // an out-of-rank array under-classifies the destination.
    for (const p of PROVIDER_REGISTRY) {
      const byRank = [...p.defaultDataClasses].sort(
        (a, b) => DATA_CLASS_ORDER.indexOf(a) - DATA_CLASS_ORDER.indexOf(b),
      );
      expect(p.defaultDataClasses, `${p.id} is not sorted by sensitivity`).toEqual(byRank);
    }
  });

  it('carries no hostSuffix already covered by another suffix on the same entry', () => {
    for (const p of PROVIDER_REGISTRY) {
      for (const suffix of p.hostSuffixes) {
        const covered = p.hostSuffixes.some(
          (other) => other !== suffix && suffix.endsWith(`.${other}`),
        );
        expect(covered, `${p.id} lists ${suffix}, already matched by a broader suffix`).toBe(false);
      }
    }
  });

  it('carries no hostSuffix shared identically by two different entries', () => {
    // An identical suffix on two entries would make resolution depend on
    // declaration order (matchMostSpecificEntry's tie-break) rather than on
    // which entry actually owns the host — a silent ambiguity a more specific
    // suffix on one side is meant to resolve instead.
    const bySuffix = new Map<string, string[]>();
    for (const p of PROVIDER_REGISTRY) {
      for (const suffix of p.hostSuffixes) {
        bySuffix.set(suffix, [...(bySuffix.get(suffix) ?? []), p.id]);
      }
    }
    for (const [suffix, ids] of bySuffix) {
      expect(ids, `${suffix} is listed by more than one entry: ${ids.join(', ')}`).toHaveLength(1);
    }
  });
});

describe('NON_DATA_HOST_SUFFIXES', () => {
  const matches = (host: string, suffix: string) => host === suffix || host.endsWith(`.${suffix}`);

  it('lists only hosts covered by some registry entry’s hostSuffixes', () => {
    // Otherwise the list could rot: a host removed from every provider's
    // hostSuffixes would still be named here for no reason, and a host that
    // was never covered names nothing this resolution step would have caught
    // anyway.
    for (const host of NON_DATA_HOST_SUFFIXES) {
      const covered = PROVIDER_REGISTRY.some((p) => p.hostSuffixes.some((s) => matches(host, s)));
      expect(covered, `${host} is not covered by any registry entry's hostSuffixes`).toBe(true);
    }
  });

  it('lists no host that a registry hostSuffix equals or sits above', () => {
    // The reverse direction from the case above. A listed host must be
    // strictly more specific than every registry hostSuffix it falls under
    // — never equal to one, and never a superdomain a provider's own
    // hostSuffix sits underneath. Note the argument order: the registry
    // suffix is the candidate HOST here, and the listed doc host is the
    // SUFFIX being matched against. Otherwise `isNonDataHost` would exclude
    // that whole registry suffix — and every subdomain under it — rather
    // than only the documentation host, e.g. listing 'openai.com' here would
    // make 'api.openai.com' a non-data host too.
    for (const host of NON_DATA_HOST_SUFFIXES) {
      const swallowsARegistrySuffix = PROVIDER_REGISTRY.some((p) =>
        p.hostSuffixes.some((suffix) => matches(suffix, host)),
      );
      expect(
        swallowsARegistrySuffix,
        `${host} equals or sits above a registry entry's hostSuffix`,
      ).toBe(false);
    }
  });
});

describe('isNonDataHost', () => {
  it('is true for a listed documentation host', () => {
    expect(isNonDataHost('docs.github.com')).toBe(true);
  });

  it('is true for a subdomain of a listed documentation host', () => {
    expect(isNonDataHost('developer.docs.github.com')).toBe(true);
  });

  it('is false for a provider host that is not on the list', () => {
    expect(isNonDataHost('api.github.com')).toBe(false);
  });

  it('is false for a host with no dot boundary against a listed suffix', () => {
    expect(isNonDataHost('evildocs.github.com')).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(isNonDataHost('DOCS.GITHUB.COM')).toBe(true);
  });
});

describe('matchMostSpecificEntry', () => {
  function entry(id: string, hostSuffixes: string[]): ProviderRegistryEntry {
    return {
      id,
      name: id,
      category: 'Test',
      hostSuffixes,
      apiBase: `https://${id}.example`,
      defaultDataClasses: ['none'],
      sdks: {},
    };
  }

  it('picks the entry with the longest matching suffix, regardless of declaration order', () => {
    const apexFirst = [
      entry('apex', ['googleapis.com']),
      entry('specific', ['fonts.googleapis.com']),
    ];
    const specificFirst = [
      entry('specific', ['fonts.googleapis.com']),
      entry('apex', ['googleapis.com']),
    ];

    expect(matchMostSpecificEntry('fonts.googleapis.com', apexFirst)?.id).toBe('specific');
    expect(matchMostSpecificEntry('fonts.googleapis.com', specificFirst)?.id).toBe('specific');

    // The apex still resolves to the apex entry when the specific suffix
    // doesn't match at all.
    expect(matchMostSpecificEntry('storage.googleapis.com', apexFirst)?.id).toBe('apex');
    expect(matchMostSpecificEntry('storage.googleapis.com', specificFirst)?.id).toBe('apex');
  });

  it('falls back to declaration order when two matching suffixes tie in length', () => {
    const firstDeclared = [entry('first', ['tied.example']), entry('second', ['tied.example'])];
    expect(matchMostSpecificEntry('tied.example', firstDeclared)?.id).toBe('first');

    const reversed = [entry('second', ['tied.example']), entry('first', ['tied.example'])];
    expect(matchMostSpecificEntry('tied.example', reversed)?.id).toBe('second');
  });

  it('returns null when nothing matches', () => {
    expect(
      matchMostSpecificEntry('unrelated.example', [entry('apex', ['googleapis.com'])]),
    ).toBeNull();
  });
});

describe('EGRESS_VERSION_MATERIAL', () => {
  it(
    'is EXTRACTOR_VERSION "2" plus the serialized registry and both exclusion lists, ' +
      'and so changes with any of them',
    () => {
      expect(EGRESS_VERSION_MATERIAL).toBe(
        `2\n${JSON.stringify(PROVIDER_REGISTRY)}\n${JSON.stringify(EXCLUDED_HOST_SUFFIXES)}\n${JSON.stringify(NON_DATA_HOST_SUFFIXES)}`,
      );
    },
  );
});
