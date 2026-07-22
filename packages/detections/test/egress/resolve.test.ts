import { ResolvedEgressHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { RawEndpointHit } from '../../src/egress/extract.ts';
import type { ManifestSdkHit } from '../../src/egress/manifests.ts';
import { type FileEgressHits, resolveEgress } from '../../src/egress/resolve.ts';

function endpointHit(overrides: Partial<RawEndpointHit> = {}): RawEndpointHit {
  return {
    url: 'https://api.stripe.com/v1/charges',
    host: 'api.stripe.com',
    port: null,
    transport: 'https',
    method: 'REF',
    template: false,
    line: 1,
    snippet: "fetch('https://api.stripe.com/v1/charges')",
    ...overrides,
  };
}

function fileHits(overrides: Partial<FileEgressHits> = {}): FileEgressHits {
  return {
    file: 'src/billing.ts',
    vendored: false,
    endpoints: [],
    sdkHits: [],
    ...overrides,
  };
}

function sdkHit(overrides: Partial<ManifestSdkHit> = {}): ManifestSdkHit {
  return {
    ecosystem: 'npm',
    pkg: 'stripe',
    line: 12,
    snippet: '"stripe": "^14.0.0"',
    ...overrides,
  };
}

describe('resolveEgress — URL/IP hit resolution', () => {
  it('resolves a provider URL hit into a provider row: top data class, null network', () => {
    const hits = resolveEgress([fileHits({ endpoints: [endpointHit({ method: 'GET' })] })]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.host).toBe('api.stripe.com');
    expect(hits[0]?.kind).toBe('provider');
    expect(hits[0]?.trust).toBe('recognized');
    expect(hits[0]?.dataClass).toBe('customer');
    expect(hits[0]?.network).toBeNull();
  });

  it('resolves an unrecognized public-domain hit as external/unverified with populated network', () => {
    const hits = resolveEgress([
      fileHits({
        endpoints: [
          endpointHit({
            url: 'https://api.acme-partner.com/v1/orders',
            host: 'api.acme-partner.com',
            port: 8443,
          }),
        ],
      }),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.kind).toBe('external');
    expect(hits[0]?.trust).toBe('unverified');
    expect(hits[0]?.dataClass).toBe('none');
    expect(hits[0]?.network).toEqual({ port: 8443, geo: null, ptr: null });
  });

  it('resolves a bare public IP reference as ip/ip with populated network', () => {
    const hits = resolveEgress([
      fileHits({
        endpoints: [
          endpointHit({
            url: 'http://203.0.113.10:8080',
            host: '203.0.113.10',
            port: 8080,
            transport: 'http',
            method: 'REF',
          }),
        ],
      }),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.kind).toBe('ip');
    expect(hits[0]?.trust).toBe('ip');
    expect(hits[0]?.dataClass).toBe('none');
    expect(hits[0]?.network).toEqual({ port: 8080, geo: null, ptr: null });
  });

  it('drops a hit whose host resolveHost excludes', () => {
    const hits = resolveEgress([
      fileHits({
        endpoints: [
          endpointHit({
            url: 'http://localhost:3000/health',
            host: 'localhost',
            port: 3000,
            transport: 'http',
          }),
        ],
      }),
    ]);
    expect(hits).toEqual([]);
  });

  it('honors caller-supplied internalDomains when resolving a host', () => {
    const hits = resolveEgress(
      [
        fileHits({
          endpoints: [
            endpointHit({
              url: 'https://svc.mycorp.dev/api',
              host: 'svc.mycorp.dev',
              method: 'GET',
            }),
          ],
        }),
      ],
      { internalDomains: ['mycorp.dev'] },
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.kind).toBe('internal');
    expect(hits[0]?.trust).toBe('internal');
  });

  it('carries the call site through from the file and hit: file, line, snippet, dynamic, vendored', () => {
    const hits = resolveEgress([
      fileHits({
        file: 'vendor/lib/client.ts',
        vendored: true,
        endpoints: [
          endpointHit({
            method: 'GET',
            template: true,
            line: 7,
            snippet: "fetch('https://api.stripe.com/v1/${id}')",
          }),
        ],
      }),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.template).toBe(true);
    expect(hits[0]?.site).toEqual({
      file: 'vendor/lib/client.ts',
      line: 7,
      snippet: "fetch('https://api.stripe.com/v1/${id}')",
      dynamic: true,
      vendored: true,
    });
  });
});

describe('resolveEgress — SDK hit resolution', () => {
  it('resolves a recognized SDK dependency into a synthetic endpoint at the provider apiBase', () => {
    const hits = resolveEgress([fileHits({ file: 'package.json', sdkHits: [sdkHit()] })]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.host).toBe('api.stripe.com');
    expect(hits[0]?.kind).toBe('provider');
    expect(hits[0]?.method).toBe('SDK');
    expect(hits[0]?.transport).toBe('https');
    expect(hits[0]?.url).toBe('https://api.stripe.com');
    expect(hits[0]?.template).toBe(false);
    expect(hits[0]?.network).toBeNull();
    expect(hits[0]?.dataClass).toBe('customer');
    expect(hits[0]?.site.file).toBe('package.json');
    expect(hits[0]?.site.line).toBe(12);
  });

  it('drops an SDK hit for a package the registry does not recognize', () => {
    const hits = resolveEgress([
      fileHits({ file: 'package.json', sdkHits: [sdkHit({ pkg: 'left-pad' })] }),
    ]);
    expect(hits).toEqual([]);
  });
});

describe('resolveEgress — dedupe', () => {
  it('collapses exact-duplicate hits on (host, method, url, file, line)', () => {
    const dup = endpointHit({ method: 'GET' });
    const hits = resolveEgress([fileHits({ endpoints: [dup, { ...dup }] })]);
    expect(hits).toHaveLength(1);
  });

  it('drops a REF hit when a verb-method hit shares its (host, url)', () => {
    const refHit = endpointHit({ method: 'REF', line: 5 });
    const getHit = endpointHit({ method: 'GET', line: 9 });
    const hits = resolveEgress([fileHits({ endpoints: [refHit, getHit] })]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.method).toBe('GET');
    expect(hits[0]?.site.line).toBe(9);
  });

  it('drops a REF hit for a verb-method sibling anywhere in the batch, not only the same file', () => {
    const refHit = endpointHit({ method: 'REF' });
    const getHit = endpointHit({ method: 'GET' });
    const hits = resolveEgress([
      fileHits({ file: 'src/a.ts', endpoints: [refHit] }),
      fileHits({ file: 'src/b.ts', endpoints: [getHit] }),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.method).toBe('GET');
    expect(hits[0]?.site.file).toBe('src/b.ts');
  });

  it('keeps a REF hit when no verb-method hit shares its (host, url)', () => {
    const hits = resolveEgress([fileHits({ endpoints: [endpointHit({ method: 'REF' })] })]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.method).toBe('REF');
  });

  it('keeps a REF hit against a verb-method hit for a different url on the same host', () => {
    const refHit = endpointHit({ method: 'REF', url: 'https://api.stripe.com/v1/refunds' });
    const getHit = endpointHit({ method: 'GET', url: 'https://api.stripe.com/v1/charges' });
    const hits = resolveEgress([fileHits({ endpoints: [refHit, getHit] })]);
    expect(hits).toHaveLength(2);
    expect(new Set(hits.map((h) => h.method))).toEqual(new Set(['REF', 'GET']));
  });

  it('lets an SDK synthetic endpoint coexist with a literal endpoint of the same provider', () => {
    const hits = resolveEgress([
      fileHits({
        file: 'src/billing.ts',
        endpoints: [endpointHit({ method: 'GET', url: 'https://api.stripe.com/v1/charges' })],
      }),
      fileHits({ file: 'package.json', sdkHits: [sdkHit()] }),
    ]);
    expect(hits).toHaveLength(2);
    expect(new Set(hits.map((h) => h.host))).toEqual(new Set(['api.stripe.com']));
    expect(new Set(hits.map((h) => h.method))).toEqual(new Set(['GET', 'SDK']));
  });
});

describe('resolveEgress — schema conformance', () => {
  it('every resolved hit parses as ResolvedEgressHit', () => {
    const hits = resolveEgress([
      fileHits({
        file: 'src/billing.ts',
        vendored: true,
        endpoints: [
          endpointHit({ method: 'GET' }),
          endpointHit({
            url: 'https://api.acme-partner.com/v1',
            host: 'api.acme-partner.com',
            method: 'POST',
            line: 4,
          }),
          endpointHit({
            url: 'http://203.0.113.10:8080',
            host: '203.0.113.10',
            port: 8080,
            transport: 'http',
            method: 'REF',
            line: 6,
          }),
        ],
      }),
      fileHits({ file: 'package.json', sdkHits: [sdkHit()] }),
    ]);

    expect(hits.length).toBeGreaterThan(0);
    for (const hit of hits) {
      expect(() => ResolvedEgressHit.parse(hit)).not.toThrow();
    }
  });
});
