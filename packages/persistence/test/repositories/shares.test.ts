import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import { SqliteSharesRepository } from '../../src/repositories/shares.ts';
import { purgeSampleData } from '../../src/sample-purge.ts';
import { seedSampleFixtures } from '../../src/test-fixtures/index.ts';

let db: DatabaseSync;
let shares: SqliteSharesRepository;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  applyMigrations(db);
  shares = new SqliteSharesRepository(db);
});

afterEach(() => {
  db.close();
});

// Insert a real (provenance='scan') destination directly, bypassing the fixtures,
// so the isolation tests can prove purgeSampleData leaves real egress alone.
function insertScanDestination(host: string): string {
  const id = randomUUID();
  const now = Date.now();
  db.prepare(
    `INSERT INTO share_destination
       (id, kind, name, host, category, trust, last_seen, provenance, created_at, updated_at)
     VALUES (?, 'provider', ?, ?, 'Scanned', 'recognized', ?, 'scan', ?, ?)`,
  ).run(id, host, host, now, now, now);
  return id;
}

describe('SqliteSharesRepository over the sample dataset', () => {
  beforeEach(() => {
    seedSampleFixtures(db);
  });

  it('stats aggregates the whole corpus', async () => {
    const stats = await shares.stats();
    expect(stats).toEqual({
      destinations: 5,
      endpoints: 7,
      callSites: 8,
      needsReview: 2,
      insecure: 1,
      byKind: { provider: 2, internal: 2, external: 0, ip: 1 },
      byTrust: { recognized: 2, internal: 1, unverified: 1, ip: 1 },
    });
  });

  it('groups destinations provider → internal → ip', async () => {
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    expect(groups.map((g) => g.kind)).toEqual(['provider', 'internal', 'ip']);
    expect(groups.map((g) => g.total)).toEqual([2, 2, 1]);
  });

  it('derives status, rollups and review posture per destination', async () => {
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    const all = groups.flatMap((g) => g.items);

    const prometheus = all.find((d) => d.host === 'prometheus-obs.io');
    expect(prometheus).toBeDefined();
    expect(prometheus?.status).toBe('allowed');
    expect(prometheus?.isCustom).toBe(false);
    expect(prometheus?.transports).toEqual(['https']);
    // DATA_CLASS_ORDER puts telemetry before logs.
    expect(prometheus?.dataClasses).toEqual(['telemetry', 'logs']);
    expect(prometheus?.endpointCount).toBe(2);
    expect(prometheus?.callSiteCount).toBe(3);
    expect(prometheus?.review.needsReview).toBe(false);

    // The raw-IP destination carries an explicit block decision in the seed.
    const ip = all.find((d) => d.kind === 'ip');
    expect(ip?.status).toBe('blocked');
    expect(ip?.isCustom).toBe(true);
    expect(ip?.review.needsReview).toBe(true);
    expect(ip?.review.reasons).toEqual(['raw_ip', 'plaintext_transport']);
    expect(ip?.network).toEqual({ port: 8080, geo: 'Unknown · AS63949 Akamai/Linode', ptr: null });
  });

  it('filters by kind and free-text q', async () => {
    const byKind = await shares.listDestinations({
      groupBy: 'destination',
      review: false,
      kind: ['ip'],
    });
    expect(byKind.groups.map((g) => g.kind)).toEqual(['ip']);

    // q reaches call-site project/file, not just the destination name.
    const byProject = await shares.listDestinations({
      groupBy: 'destination',
      review: false,
      q: 'matching-core',
    });
    const hosts = byProject.groups.flatMap((g) => g.items).map((d) => d.host);
    expect(hosts).toEqual(['203.0.113.6']);
  });

  it('orders the needs-review strip by severity (raw_ip before unverified)', async () => {
    const { items } = await shares.needsReview();
    expect(items.map((d) => d.host)).toEqual(['203.0.113.6', 'acme-partner.com']);
    expect(items[0]?.topDataClass).toBe('telemetry');
    expect(items[1]?.review.reasons).toEqual(['unverified_domain']);
  });

  it('returns full detail with embedded call sites, null for unknown', async () => {
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    const prometheuId = groups
      .flatMap((g) => g.items)
      .find((d) => d.host === 'prometheus-obs.io')?.id;
    expect(prometheuId).toBeDefined();

    const detail = await shares.getDestination(prometheuId ?? '');
    expect(detail?.host).toBe('prometheus-obs.io');
    expect(detail?.endpoints).toHaveLength(2);
    const totalSites = detail?.endpoints.reduce((n, e) => n + e.sites.length, 0);
    expect(totalSites).toBe(3);

    expect(await shares.getDestination('does-not-exist')).toBeNull();
  });

  it('setEgressDecision toggles status and reverts on clear', async () => {
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    const prometheuId = groups
      .flatMap((g) => g.items)
      .find((d) => d.host === 'prometheus-obs.io')?.id;

    expect(shares.setEgressDecision(prometheuId ?? '', 'block')).toBe(true);
    let detail = await shares.getDestination(prometheuId ?? '');
    expect(detail?.status).toBe('blocked');
    expect(detail?.isCustom).toBe(true);

    expect(shares.setEgressDecision(prometheuId ?? '', null)).toBe(true);
    detail = await shares.getDestination(prometheuId ?? '');
    expect(detail?.status).toBe('allowed');
    expect(detail?.isCustom).toBe(false);

    expect(shares.setEgressDecision('does-not-exist', 'block')).toBe(false);
  });
});

describe('legacy sample purge', () => {
  it('purgeSampleData removes only sample rows, leaving real egress', async () => {
    seedSampleFixtures(db);
    const scanId = insertScanDestination('real.example.com');

    purgeSampleData(db);

    const stats = await shares.stats();
    expect(stats.destinations).toBe(1);
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    expect(groups.flatMap((g) => g.items).map((d) => d.id)).toEqual([scanId]);
    // No orphaned children left behind.
    const endpoints = (
      db.prepare('SELECT count(*) AS n FROM share_endpoint').get() as { n: number }
    ).n;
    expect(endpoints).toBe(0);
  });

  it('is a no-op on a store with only real shares', async () => {
    const scanId = insertScanDestination('real.example.com');
    purgeSampleData(db);
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    expect(groups.flatMap((g) => g.items).map((d) => d.id)).toEqual([scanId]);
  });
});
