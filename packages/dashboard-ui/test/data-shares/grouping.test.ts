import { describe, expect, it } from 'vitest';

import {
  foldedProviderRowId,
  groupByProvider,
  PROVIDER_ROW_PREFIX,
} from '../../src/data-shares/grouping.ts';
import { destination } from './fixtures.ts';

describe('groupByProvider', () => {
  it('folds two hosts sharing a providerId into one provider row, in input order', () => {
    const older = destination({
      id: 'gh-1',
      name: 'GitHub',
      host: 'api.github.com',
      providerId: 'github',
      category: 'Dev tools',
      lastSeen: '2026-07-01T00:00:00.000Z',
      endpointCount: 2,
      callSiteCount: 3,
      transports: ['https'],
      dataClasses: ['source'],
    });
    const newer = destination({
      id: 'gh-2',
      name: 'GitHub Raw',
      host: 'raw.githubusercontent.com',
      providerId: 'github',
      category: 'Dev tools',
      lastSeen: '2026-07-05T00:00:00.000Z',
      endpointCount: 1,
      callSiteCount: 4,
      transports: ['http'],
      dataClasses: ['pii'],
    });
    const external = destination({
      id: 'ext-1',
      name: 'Acme Analytics',
      host: 'acme-analytics.io',
      providerId: null,
    });

    const rows = groupByProvider([older, newer, external]);

    expect(rows).toEqual([
      {
        type: 'provider',
        group: {
          id: 'provider:github',
          providerId: 'github',
          // The most recently seen host's name/category.
          name: 'GitHub Raw',
          category: 'Dev tools',
          hosts: [older, newer],
          endpointCount: 3,
          callSiteCount: 7,
          transports: ['https', 'http'],
          dataClasses: ['pii', 'source'],
          lastSeen: '2026-07-05T00:00:00.000Z',
          insecure: true,
        },
      },
      { type: 'destination', item: external },
    ]);
    expect(rows[0]).toMatchObject({ group: { id: PROVIDER_ROW_PREFIX + 'github' } });
  });

  it('unions transports and data classes without duplicates', () => {
    const a = destination({
      id: 'a',
      providerId: 'p',
      transports: ['https'],
      dataClasses: ['pii'],
    });
    const b = destination({
      id: 'b',
      providerId: 'p',
      transports: ['https', 'http'],
      dataClasses: ['pii', 'source'],
    });

    const rows = groupByProvider([a, b]);

    expect(rows).toHaveLength(1);
    const [row] = rows;
    if (row?.type !== 'provider') throw new Error('expected a provider row');
    expect(row.group.transports).toEqual(['https', 'http']);
    expect(row.group.dataClasses).toEqual(['pii', 'source']);
  });

  it('orders the folded data classes most-sensitive first, whichever host contributes them', () => {
    const first = destination({
      id: 'first',
      providerId: 'p',
      dataClasses: ['customer', 'source', 'telemetry'],
    });
    const last = destination({ id: 'last', providerId: 'p', dataClasses: ['secrets'] });

    const [row] = groupByProvider([first, last]);

    if (row?.type !== 'provider') throw new Error('expected a provider row');
    expect(row.group.dataClasses).toEqual(['secrets', 'customer', 'source', 'telemetry']);
  });

  it('leaves a lone provider host as a plain destination row', () => {
    const solo = destination({ id: 'solo', providerId: 'okta' });

    const rows = groupByProvider([solo]);

    expect(rows).toEqual([{ type: 'destination', item: solo }]);
  });

  // Positive control: two rows sharing a NAME but carrying no providerId must
  // never fold — only a shared providerId groups rows.
  it('never folds destinations with providerId: null, even when their names match', () => {
    const a = destination({ id: 'a', name: 'Duplicate Name', providerId: null });
    const b = destination({ id: 'b', name: 'Duplicate Name', providerId: null });

    const rows = groupByProvider([a, b]);

    expect(rows).toEqual([
      { type: 'destination', item: a },
      { type: 'destination', item: b },
    ]);
  });

  // Positive control: two rows sharing a providerId but carrying a non-provider
  // kind must never fold — a matched provider registry entry only ever
  // resolves to kind 'provider', so this guards against a stale or
  // reclassified row that still carries the old providerId.
  it('never folds destinations sharing a providerId when their kind is not provider', () => {
    const a = destination({ id: 'a', kind: 'external', providerId: 'p' });
    const b = destination({ id: 'b', kind: 'external', providerId: 'p' });

    const rows = groupByProvider([a, b]);

    expect(rows).toEqual([
      { type: 'destination', item: a },
      { type: 'destination', item: b },
    ]);
  });

  it('preserves row order at the position of each group’s first member', () => {
    const first = destination({ id: 'first', providerId: null, name: 'First' });
    const ghA = destination({ id: 'gh-a', providerId: 'github', name: 'GitHub A' });
    const middle = destination({ id: 'middle', providerId: null, name: 'Middle' });
    const ghB = destination({ id: 'gh-b', providerId: 'github', name: 'GitHub B' });
    const last = destination({ id: 'last', providerId: null, name: 'Last' });

    const rows = groupByProvider([first, ghA, middle, ghB, last]);

    expect(rows.map((r) => (r.type === 'destination' ? r.item.id : r.group.id))).toEqual([
      'first',
      'provider:github',
      'middle',
      'last',
    ]);
  });

  it('sums endpoint and call-site counts across hosts', () => {
    const a = destination({ id: 'a', providerId: 'p', endpointCount: 2, callSiteCount: 5 });
    const b = destination({ id: 'b', providerId: 'p', endpointCount: 3, callSiteCount: 1 });

    const rows = groupByProvider([a, b]);

    expect(rows[0]).toMatchObject({ group: { endpointCount: 5, callSiteCount: 6 } });
  });

  it('reports insecure only when at least one host sends over a plaintext transport', () => {
    const secureOnly = groupByProvider([
      destination({ id: 'a', providerId: 'p', transports: ['https'] }),
      destination({ id: 'b', providerId: 'p', transports: ['https'] }),
    ]);
    expect(secureOnly[0]).toMatchObject({ group: { insecure: false } });

    const oneInsecure = groupByProvider([
      destination({ id: 'a', providerId: 'p', transports: ['https'] }),
      destination({ id: 'b', providerId: 'p', transports: ['http'] }),
    ]);
    expect(oneInsecure[0]).toMatchObject({ group: { insecure: true } });
  });
});

describe('foldedProviderRowId', () => {
  it('returns the provider row id for a member of a folded bucket', () => {
    const a = destination({ id: 'a', providerId: 'github' });
    const b = destination({ id: 'b', providerId: 'github' });

    expect(foldedProviderRowId([a, b], 'a')).toBe(PROVIDER_ROW_PREFIX + 'github');
    expect(foldedProviderRowId([a, b], 'b')).toBe(PROVIDER_ROW_PREFIX + 'github');
  });

  it('returns null for the sole host of a provider nobody else shares', () => {
    const solo = destination({ id: 'solo', providerId: 'okta' });

    expect(foldedProviderRowId([solo], 'solo')).toBeNull();
  });

  it('returns null for a destination with providerId: null', () => {
    const a = destination({ id: 'a', providerId: null });
    const b = destination({ id: 'b', providerId: null });

    expect(foldedProviderRowId([a, b], 'a')).toBeNull();
  });

  it('returns null for a non-provider kind sharing a providerId with another host', () => {
    const a = destination({ id: 'a', kind: 'external', providerId: 'p' });
    const b = destination({ id: 'b', kind: 'external', providerId: 'p' });

    expect(foldedProviderRowId([a, b], 'a')).toBeNull();
  });

  it('returns null when the id is not in the list', () => {
    const a = destination({ id: 'a', providerId: 'github' });
    const b = destination({ id: 'b', providerId: 'github' });

    expect(foldedProviderRowId([a, b], 'gone')).toBeNull();
  });
});
