import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { DestinationKind, EgressEcosystem, ShareTrustLevel } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  EGRESS_VERSION_MATERIAL,
  PROVIDER_REGISTRY,
  resolveHost,
  resolveSdk,
} from '../../src/egress/registry.ts';

const fixturesDir = join(
  fileURLToPath(new URL('.', import.meta.url)),
  '../../src/egress/fixtures',
);

interface HostCase {
  label: string;
  host: string;
  opts?: { internalDomains?: string[] };
  expect: { kind: DestinationKind; trust: ShareTrustLevel; name: string } | null;
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
    }
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

  it('has 35 seeded providers, each with at least one hostSuffix and one dataClass', () => {
    expect(PROVIDER_REGISTRY.length).toBe(35);
    for (const p of PROVIDER_REGISTRY) {
      expect(p.hostSuffixes.length).toBeGreaterThanOrEqual(1);
      expect(p.defaultDataClasses.length).toBeGreaterThanOrEqual(1);
    }
  });
});

describe('EGRESS_VERSION_MATERIAL', () => {
  it('is EXTRACTOR_VERSION "1" plus the serialized registry, and so changes with the registry', () => {
    expect(EGRESS_VERSION_MATERIAL).toBe(`1\n${JSON.stringify(PROVIDER_REGISTRY)}`);
  });

  it('differs from the material a different registry array would produce', () => {
    const mutated = [...PROVIDER_REGISTRY, { ...PROVIDER_REGISTRY[0], id: 'zzz-not-real' }];
    const mutatedMaterial = `1\n${JSON.stringify(mutated)}`;
    expect(mutatedMaterial).not.toBe(EGRESS_VERSION_MATERIAL);
  });
});
