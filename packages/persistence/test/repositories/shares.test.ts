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

/** One endpoint on a destination, so transport-sensitive reads have a row to see. */
function insertScanEndpoint(destinationId: string, transport: string, url: string): string {
  const id = randomUUID();
  const now = Date.now();
  db.prepare(
    `INSERT INTO share_endpoint
       (id, destination_id, method, transport, url, data_class, last_seen, created_at, updated_at)
     VALUES (?, ?, 'REF', ?, ?, 'none', ?, ?, ?)`,
  ).run(id, destinationId, transport, url, now, now, now);
  return id;
}

/** An override row written directly, so the host/legacy join arms can be driven apart. */
function insertOverride(destinationId: string, host: string | null, decision: string): void {
  const now = Date.now();
  db.prepare(
    `INSERT INTO egress_decision_override (id, destination_id, host, decision, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(randomUUID(), destinationId, host, decision, now, now);
}

describe('SqliteSharesRepository over the sample dataset', () => {
  beforeEach(() => {
    seedSampleFixtures(db);
  });

  it('stats aggregates the whole corpus', async () => {
    const stats = await shares.stats();
    expect(stats).toEqual({
      destinations: 6,
      endpoints: 8,
      callSites: 9,
      // The three risky-trust destinations: the raw IP and the two unverified
      // domains. The corpus's only plaintext endpoint is the IP's `http` one —
      // the external destination's `wss` stream is secure and must not count.
      needsReview: 3,
      insecure: 1,
      byKind: { provider: 2, internal: 2, external: 1, ip: 1 },
      byTrust: { recognized: 2, internal: 1, unverified: 2, ip: 1 },
    });
  });

  it('groups destinations provider → internal → external → ip', async () => {
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    expect(groups.map((g) => g.kind)).toEqual(['provider', 'internal', 'external', 'ip']);
    expect(groups.map((g) => g.total)).toEqual([2, 2, 1, 1]);

    // The external destination is carried in the response, not just labelled —
    // a kind missing from KIND_ORDER is dropped from the payload entirely.
    const external = groups.find((g) => g.kind === 'external');
    expect(external?.items.map((d) => d.host)).toEqual(['analytics-vendor.com']);
    expect(external?.items[0]?.trust).toBe('unverified');
    expect(external?.items[0]?.transports).toEqual(['wss']);
    expect(external?.items[0]?.endpoints[0]?.method).toBe('REF');
    expect(external?.items[0]?.review.reasons).toEqual(['unverified_domain']);
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
    // Equal severity falls back to most-recently-seen first, so the external
    // destination (45 min) precedes acme-partner (300 min).
    expect(items.map((d) => d.host)).toEqual([
      '203.0.113.6',
      'analytics-vendor.com',
      'acme-partner.com',
    ]);
    expect(items[0]?.topDataClass).toBe('telemetry');
    expect(items[1]?.kind).toBe('external');
    expect(items[1]?.review.reasons).toEqual(['unverified_domain']);
    expect(items[2]?.review.reasons).toEqual(['unverified_domain']);
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

  it('setEgressDecision records the host and replaces a legacy host-NULL row', async () => {
    // The seeded IP destination carries a legacy override written without a
    // host — the shape already-shipped binaries produce.
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    const ip = groups.flatMap((g) => g.items).find((d) => d.kind === 'ip');
    const ipId = ip?.id ?? '';
    expect(ip?.status).toBe('blocked');
    expect(
      db.prepare('SELECT host FROM egress_decision_override WHERE destination_id = ?').all(ipId),
    ).toEqual([{ host: null }]);

    expect(shares.setEgressDecision(ipId, 'allow')).toBe(true);

    // Exactly one row survives, now carrying BOTH keys.
    expect(
      db.prepare('SELECT destination_id, host, decision FROM egress_decision_override').all(),
    ).toEqual([{ destination_id: ipId, host: '203.0.113.6', decision: 'allow' }]);
    expect((await shares.getDestination(ipId))?.status).toBe('allowed');

    // Clearing removes the host-keyed row too, reverting to the trust default.
    expect(shares.setEgressDecision(ipId, null)).toBe(true);
    expect(db.prepare('SELECT count(*) AS n FROM egress_decision_override').get()).toEqual({ n: 0 });
    expect((await shares.getDestination(ipId))?.status).toBe('review');
  });
});

describe('host-keyed egress decisions', () => {
  it('matches a host-bearing override by host, not by its destination id', async () => {
    // Both destinations here are LIVE — this is the matching rule, not survival
    // (covered below). A row carrying a host attaches to whichever destination
    // holds that host, and its own destination_id is ignored: `ol` only matches
    // host-NULL rows, so the row cannot also drag the decision onto b.example.com.
    const current = insertScanDestination('a.example.com');
    const stale = insertScanDestination('b.example.com');
    insertOverride(stale, 'a.example.com', 'block');

    expect((await shares.getDestination(current))?.status).toBe('blocked');
    expect((await shares.getDestination(current))?.isCustom).toBe(true);
    expect((await shares.getDestination(stale))?.status).toBe('allowed');
    expect((await shares.getDestination(stale))?.isCustom).toBe(false);
  });

  it('survives its destination being pruned and re-attaches when the host returns', async () => {
    // The point of the host column, end to end. destination_id is nullable
    // under ON DELETE SET NULL, so pruning the destination clears the pointer
    // rather than raising FOREIGN KEY constraint failed — and the surviving
    // row re-attaches by host when the same host is detected under a fresh id.
    const original = insertScanDestination('pruned.example.com');
    insertOverride(original, 'pruned.example.com', 'block');

    db.prepare('DELETE FROM share_destination WHERE id = ?').run(original);

    expect(
      db.prepare('SELECT destination_id, host, decision FROM egress_decision_override').all(),
    ).toEqual([{ destination_id: null, host: 'pruned.example.com', decision: 'block' }]);

    const rediscovered = insertScanDestination('pruned.example.com');
    expect(rediscovered).not.toBe(original);
    expect((await shares.getDestination(rediscovered))?.status).toBe('blocked');
    expect((await shares.getDestination(rediscovered))?.isCustom).toBe(true);
  });

  it('still honours a legacy host-NULL override via destination_id', async () => {
    const id = insertScanDestination('legacy.example.com');
    insertOverride(id, null, 'block');

    expect((await shares.getDestination(id))?.status).toBe('blocked');
    const { groups } = await shares.listDestinations({ groupBy: 'destination', review: false });
    expect(groups.flatMap((g) => g.items).find((d) => d.id === id)?.status).toBe('blocked');
  });

  it('prefers the host match over a legacy row matching the same destination', async () => {
    // uq_egress_decision_override keeps one row per destination_id, so the two
    // arms can only collide across rows: a legacy row pointing AT this
    // destination, and a host row for its host parked on another one.
    const id = insertScanDestination('both.example.com');
    const other = insertScanDestination('other.example.com');
    insertOverride(id, null, 'allow');
    insertOverride(other, 'both.example.com', 'block');

    expect((await shares.getDestination(id))?.status).toBe('blocked');
  });

  it('applies the host join on the search branch of the listing too', async () => {
    // fetchDestinations emits a separate SELECT DISTINCT when `q` is set; the
    // two branches must not disagree about a destination's decision.
    const id = insertScanDestination('searchable.example.com');
    insertOverride(id, 'searchable.example.com', 'block');

    const { groups } = await shares.listDestinations({
      groupBy: 'destination',
      review: false,
      q: 'searchable',
    });
    expect(groups.flatMap((g) => g.items).map((d) => d.status)).toEqual(['blocked']);
  });
});

describe('plaintext transports (http and ws)', () => {
  it('counts ws as plaintext in stats, and wss as secure', async () => {
    const plain = insertScanDestination('ws.example.com');
    insertScanEndpoint(plain, 'ws', 'ws://ws.example.com/stream');
    const secure = insertScanDestination('wss.example.com');
    insertScanEndpoint(secure, 'wss', 'wss://wss.example.com/stream');

    const stats = await shares.stats();
    expect(stats.insecure).toBe(1);
    expect(stats.needsReview).toBe(1);
  });

  it('surfaces a ws-only destination in the needs-review strip', async () => {
    const plain = insertScanDestination('ws.example.com');
    insertScanEndpoint(plain, 'ws', 'ws://ws.example.com/stream');
    insertScanDestination('wss.example.com');

    const { items } = await shares.needsReview();
    expect(items.map((d) => d.host)).toEqual(['ws.example.com']);
    expect(items[0]?.review.reasons).toEqual(['plaintext_transport']);
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
