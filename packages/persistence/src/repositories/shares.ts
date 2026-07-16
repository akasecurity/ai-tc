import { randomUUID } from 'node:crypto';
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import type {
  CallSite,
  DataClass,
  DestinationKind,
  EgressDecision,
  EndpointSummary,
  HttpMethod,
  ListShareDestinationsQuery,
  ListShareDestinationsResponse,
  NeedsReviewResponse,
  ReviewDestination,
  ShareDestinationDetail,
  ShareDestinationGroup,
  ShareDestinationSummary,
  SharesStats,
  ShareTrustLevel,
  Transport,
} from '@akasecurity/schema';
import {
  buildReviewInfo,
  distinctDataClasses,
  distinctTransports,
  effectiveStatus,
  isCustomDecision,
  reviewSeverityRank,
  topDataClass,
} from '@akasecurity/schema';

import { safeJson } from '../internal/json.ts';
import { allRows, countBy, countScalar, getRow } from '../internal/rows.ts';
import { containsPattern, placeholders } from '../internal/sql-text.ts';
import type { SharesReadPort } from '../ports.ts';

// Section order for the grouped listing — provider → internal → ip.
const KIND_ORDER: DestinationKind[] = ['provider', 'internal', 'ip'];

// Defensive bound on call sites embedded in a destination detail, so a runaway
// destination can't inflate the read.
const CALL_SITE_EMBED_CAP = 200;

// ─── Raw row shapes (post-projection, JS-normalised) ─────────────────────────

interface DestRow {
  id: string;
  kind: DestinationKind;
  name: string;
  host: string;
  category: string;
  trust: ShareTrustLevel;
  note: string | null;
  networkJson: string | null;
  lastSeenMs: number;
  overrideDecision: EgressDecision | null;
}

interface EndpointRow {
  id: string;
  destinationId: string;
  method: HttpMethod;
  transport: Transport;
  url: string;
  template: boolean;
  dataClass: DataClass;
  lastSeenMs: number;
  callSiteCount: number;
}

interface CallSiteRow {
  id: string;
  endpointId: string;
  project: string;
  file: string;
  line: number;
  snippet: string;
  dynamic: boolean;
  vendored: boolean;
  projectId: string | null;
}

function parseNetwork(networkJson: string | null): ShareDestinationSummary['network'] {
  return safeJson<ShareDestinationSummary['network']>(networkJson, null);
}

function toEndpointSummary(row: EndpointRow): EndpointSummary {
  return {
    id: row.id,
    method: row.method,
    transport: row.transport,
    url: row.url,
    template: row.template,
    dataClass: row.dataClass,
    lastSeen: new Date(row.lastSeenMs).toISOString(),
    callSiteCount: row.callSiteCount,
  };
}

function toCallSite(row: CallSiteRow): CallSite {
  return {
    id: row.id,
    project: row.project,
    file: row.file,
    line: row.line,
    snippet: row.snippet,
    dynamic: row.dynamic,
    vendored: row.vendored,
    projectId: row.projectId,
  };
}

/** Assembles a ShareDestinationSummary from a destination row + its endpoints. */
function buildSummary(dest: DestRow, endpoints: EndpointRow[]): ShareDestinationSummary {
  const transports = endpoints.map((e) => e.transport);
  const dataClasses = endpoints.map((e) => e.dataClass);
  const callSiteCount = endpoints.reduce((sum, e) => sum + e.callSiteCount, 0);
  const lastSeenMs =
    endpoints.length > 0 ? Math.max(...endpoints.map((e) => e.lastSeenMs)) : dest.lastSeenMs;

  return {
    id: dest.id,
    kind: dest.kind,
    name: dest.name,
    host: dest.host,
    category: dest.category,
    trust: dest.trust,
    status: effectiveStatus(dest.trust, dest.overrideDecision),
    isCustom: isCustomDecision(dest.trust, dest.overrideDecision),
    lastSeen: new Date(lastSeenMs).toISOString(),
    endpointCount: endpoints.length,
    callSiteCount,
    transports: distinctTransports(transports),
    dataClasses: distinctDataClasses(dataClasses),
    review: buildReviewInfo(dest.trust, transports),
    network: dest.kind === 'provider' ? null : parseNetwork(dest.networkJson),
    endpoints: endpoints.map(toEndpointSummary),
  };
}

/** Assembles a ShareDestinationDetail — destination → endpoint → call site. */
function buildDetail(
  dest: DestRow,
  endpoints: EndpointRow[],
  callSites: CallSiteRow[],
): ShareDestinationDetail {
  const transports = endpoints.map((e) => e.transport);
  const lastSeenMs =
    endpoints.length > 0 ? Math.max(...endpoints.map((e) => e.lastSeenMs)) : dest.lastSeenMs;

  const sitesByEndpoint = new Map<string, CallSite[]>();
  for (const site of callSites.slice(0, CALL_SITE_EMBED_CAP)) {
    const mapped = toCallSite(site);
    const arr = sitesByEndpoint.get(site.endpointId);
    if (arr) arr.push(mapped);
    else sitesByEndpoint.set(site.endpointId, [mapped]);
  }

  return {
    id: dest.id,
    kind: dest.kind,
    name: dest.name,
    host: dest.host,
    category: dest.category,
    trust: dest.trust,
    status: effectiveStatus(dest.trust, dest.overrideDecision),
    isCustom: isCustomDecision(dest.trust, dest.overrideDecision),
    lastSeen: new Date(lastSeenMs).toISOString(),
    transports: distinctTransports(transports),
    dataClasses: distinctDataClasses(endpoints.map((e) => e.dataClass)),
    review: buildReviewInfo(dest.trust, transports),
    network: dest.kind === 'provider' ? null : parseNetwork(dest.networkJson),
    note: dest.note,
    endpoints: endpoints.map((ep) => ({
      ...toEndpointSummary(ep),
      sites: sitesByEndpoint.get(ep.id) ?? [],
    })),
  };
}

/**
 * Data Shares read views over the tenant-free local store — the read side of
 * the Data Shares page. Reads share_destination/endpoint/call_site (+ the egress
 * decision override) and shapes the finished @akasecurity/schema responses.
 * The local store IS the shares service, so it
 * both fetches and assembles here (mirrors SqliteDetectionsRepository /
 * SqliteSecurityRepository). Writes (setEgressDecision) surface errors to the
 * caller — they run off the hook path, driven by a web-ui Server Action.
 */
export class SqliteSharesRepository implements SharesReadPort {
  constructor(private readonly db: DatabaseSync) {}

  stats(): Promise<SharesStats> {
    const destinations = countScalar(this.db, 'SELECT count(*) AS n FROM share_destination');
    const endpoints = countScalar(this.db, 'SELECT count(*) AS n FROM share_endpoint');
    const callSites = countScalar(this.db, 'SELECT count(*) AS n FROM share_call_site');
    const insecure = countScalar(
      this.db,
      "SELECT count(DISTINCT destination_id) AS n FROM share_endpoint WHERE transport = 'http'",
    );
    const needsReview = countScalar(
      this.db,
      `SELECT count(DISTINCT d.id) AS n
       FROM share_destination d
       LEFT JOIN share_endpoint e ON e.destination_id = d.id AND e.transport = 'http'
       WHERE d.trust IN ('unverified', 'ip') OR e.id IS NOT NULL`,
    );

    const kindCounts = countBy(
      this.db,
      'SELECT kind AS k, count(*) AS n FROM share_destination GROUP BY kind',
    );
    const byKind: SharesStats['byKind'] = {
      provider: kindCounts.get('provider') ?? 0,
      internal: kindCounts.get('internal') ?? 0,
      ip: kindCounts.get('ip') ?? 0,
    };

    const trustCounts = countBy(
      this.db,
      'SELECT trust AS k, count(*) AS n FROM share_destination GROUP BY trust',
    );
    const byTrust: SharesStats['byTrust'] = {
      recognized: trustCounts.get('recognized') ?? 0,
      internal: trustCounts.get('internal') ?? 0,
      unverified: trustCounts.get('unverified') ?? 0,
      ip: trustCounts.get('ip') ?? 0,
    };

    return Promise.resolve({
      destinations,
      endpoints,
      callSites,
      needsReview,
      insecure,
      byKind,
      byTrust,
    });
  }

  listDestinations(query: ListShareDestinationsQuery): Promise<ListShareDestinationsResponse> {
    const q = query.q === undefined || query.q === '' ? undefined : query.q;
    const dests = this.fetchDestinations(q, query.kind);
    const endpointsByDest = this.groupEndpoints(dests.map((d) => d.id));
    const summaries = dests.map((d) => buildSummary(d, endpointsByDest.get(d.id) ?? []));

    const grouped = new Map<DestinationKind, ShareDestinationSummary[]>();
    for (const s of summaries) {
      const arr = grouped.get(s.kind);
      if (arr) arr.push(s);
      else grouped.set(s.kind, [s]);
    }

    const groups: ShareDestinationGroup[] = KIND_ORDER.filter((kind) => grouped.has(kind)).map(
      (kind) => {
        const items = grouped.get(kind) ?? [];
        return { kind, total: items.length, items };
      },
    );

    return Promise.resolve({ groups });
  }

  needsReview(): Promise<NeedsReviewResponse> {
    // review covers every kind regardless of the grouped view's filter. The SQL
    // pre-filter narrows to review candidates so we don't build+discard a full
    // summary for every clean destination; the buildReviewInfo filter below stays
    // authoritative (the SQL predicate is a superset that mirrors it), so the two
    // can't silently disagree on what "needs review" means.
    const dests = this.fetchDestinations(undefined, undefined, true);
    const endpointsByDest = this.groupEndpoints(dests.map((d) => d.id));

    const items: ReviewDestination[] = dests
      .map((d) => ({ dest: d, endpoints: endpointsByDest.get(d.id) ?? [] }))
      .map(({ dest, endpoints }) => ({ summary: buildSummary(dest, endpoints), endpoints }))
      .filter(({ summary }) => summary.review.needsReview)
      .map(({ summary, endpoints }): ReviewDestination => ({
        id: summary.id,
        kind: summary.kind,
        name: summary.name,
        host: summary.host,
        trust: summary.trust,
        status: summary.status,
        review: summary.review,
        topDataClass: topDataClass(endpoints.map((e) => e.dataClass)),
        callSiteCount: summary.callSiteCount,
        lastSeen: summary.lastSeen,
      }))
      .sort((a, b) => {
        const rankDiff =
          reviewSeverityRank(a.review.reasons) - reviewSeverityRank(b.review.reasons);
        if (rankDiff !== 0) return rankDiff;
        // Fixed-width ISO-8601 UTC strings sort lexicographically == chronologically;
        // descending = most-recent first.
        return b.lastSeen.localeCompare(a.lastSeen);
      });

    return Promise.resolve({ items });
  }

  getDestination(destinationId: string): Promise<ShareDestinationDetail | null> {
    const dest = this.fetchDestinationById(destinationId);
    if (!dest) return Promise.resolve(null);
    const endpoints = this.fetchEndpoints([dest.id]);
    const callSites = this.fetchCallSites(endpoints.map((e) => e.id));
    return Promise.resolve(buildDetail(dest, endpoints, callSites));
  }

  // ─── Writes ────────────────────────────────────────────────────────────────
  // Driven by a web-ui Server Action, not the hook path — errors surface to the
  // caller. Returns whether the destination existed, so the caller can tell a
  // real edit from a no-such-destination.

  /**
   * Set (decision) or clear (null) the egress decision override for a destination.
   * `null` deletes the override row → reverts to the trust default.
   */
  setEgressDecision(destinationId: string, decision: EgressDecision | null): boolean {
    const exists = this.db
      .prepare('SELECT 1 FROM share_destination WHERE id = ?')
      .get(destinationId);
    if (exists === undefined) return false;

    if (decision === null) {
      this.db
        .prepare('DELETE FROM egress_decision_override WHERE destination_id = ?')
        .run(destinationId);
      return true;
    }
    this.db
      .prepare(
        `INSERT INTO egress_decision_override (id, destination_id, decision, created_at, updated_at)
         VALUES (:id, :destinationId, :decision, :now, :now)
         ON CONFLICT (destination_id) DO UPDATE SET
           decision = excluded.decision,
           updated_at = excluded.updated_at`,
      )
      .run({ id: randomUUID(), destinationId, decision, now: Date.now() });
    return true;
  }

  // ─── Raw fetchers ────────────────────────────────────────────────────────────

  private mapDestRow(r: {
    id: string;
    kind: string;
    name: string;
    host: string;
    category: string;
    trust: string;
    note: string | null;
    networkJson: string | null;
    lastSeenMs: number;
    overrideDecision: string | null;
  }): DestRow {
    return {
      id: r.id,
      kind: r.kind as DestinationKind,
      name: r.name,
      host: r.host,
      category: r.category,
      trust: r.trust as ShareTrustLevel,
      note: r.note,
      networkJson: r.networkJson,
      lastSeenMs: r.lastSeenMs,
      overrideDecision: (r.overrideDecision as EgressDecision | null) ?? null,
    };
  }

  private fetchDestinations(
    q: string | undefined,
    kinds: DestinationKind[] | undefined,
    reviewOnly = false,
  ): DestRow[] {
    const cols = `d.id, d.kind, d.name, d.host, d.category, d.trust, d.note,
                  d.network_json AS networkJson, d.last_seen AS lastSeenMs,
                  d.created_at AS createdAt, o.decision AS overrideDecision`;
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (kinds && kinds.length > 0) {
      conditions.push(`d.kind IN (${placeholders(kinds.length)})`);
      params.push(...kinds);
    }
    if (reviewOnly) {
      // Cheap pre-filter mirroring deriveReviewReasons: risky trust, or any
      // plaintext endpoint. EXISTS (not a join) so it never fans out rows.
      conditions.push(
        `(d.trust IN ('unverified', 'ip')
          OR EXISTS (SELECT 1 FROM share_endpoint re
                     WHERE re.destination_id = d.id AND re.transport = 'http'))`,
      );
    }

    let sql: string;
    if (q) {
      const pattern = containsPattern(q);
      conditions.push(
        `(d.name LIKE ? ESCAPE '\\' OR d.category LIKE ? ESCAPE '\\' OR e.url LIKE ? ESCAPE '\\'
          OR c.project LIKE ? ESCAPE '\\' OR c.file LIKE ? ESCAPE '\\')`,
      );
      params.push(pattern, pattern, pattern, pattern, pattern);
      sql = `SELECT DISTINCT ${cols}
             FROM share_destination d
             LEFT JOIN egress_decision_override o ON o.destination_id = d.id
             LEFT JOIN share_endpoint e ON e.destination_id = d.id
             LEFT JOIN share_call_site c ON c.endpoint_id = e.id
             ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''}
             ORDER BY d.created_at ASC, d.id ASC`;
    } else {
      sql = `SELECT ${cols}
             FROM share_destination d
             LEFT JOIN egress_decision_override o ON o.destination_id = d.id
             ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''}
             ORDER BY d.created_at ASC, d.id ASC`;
    }

    const rows = allRows<Parameters<typeof this.mapDestRow>[0]>(
      this.db.prepare(sql),
      params as SQLInputValue[],
    );
    return rows.map((r) => this.mapDestRow(r));
  }

  private fetchDestinationById(destinationId: string): DestRow | null {
    const row = getRow<Parameters<typeof this.mapDestRow>[0]>(
      this.db.prepare(
        `SELECT d.id, d.kind, d.name, d.host, d.category, d.trust, d.note,
                d.network_json AS networkJson, d.last_seen AS lastSeenMs,
                o.decision AS overrideDecision
         FROM share_destination d
         LEFT JOIN egress_decision_override o ON o.destination_id = d.id
         WHERE d.id = ?`,
      ),
      [destinationId],
    );
    return row ? this.mapDestRow(row) : null;
  }

  private fetchEndpoints(destinationIds: string[]): EndpointRow[] {
    if (destinationIds.length === 0) return [];
    const rows = allRows<{
      id: string;
      destinationId: string;
      method: string;
      transport: string;
      url: string;
      template: number;
      dataClass: string;
      lastSeenMs: number;
      callSiteCount: number;
    }>(
      this.db.prepare(
        `SELECT e.id, e.destination_id AS destinationId, e.method, e.transport, e.url,
                e.template, e.data_class AS dataClass, e.last_seen AS lastSeenMs,
                count(c.id) AS callSiteCount
         FROM share_endpoint e
         LEFT JOIN share_call_site c ON c.endpoint_id = e.id
         WHERE e.destination_id IN (${placeholders(destinationIds.length)})
         GROUP BY e.id
         ORDER BY e.created_at ASC, e.id ASC`,
      ),
      destinationIds,
    );
    return rows.map((r) => ({
      id: r.id,
      destinationId: r.destinationId,
      method: r.method as HttpMethod,
      transport: r.transport as Transport,
      url: r.url,
      template: r.template === 1,
      dataClass: r.dataClass as DataClass,
      lastSeenMs: r.lastSeenMs,
      callSiteCount: r.callSiteCount,
    }));
  }

  /** listEndpointsForDestinations grouped by destination id for in-memory assembly. */
  private groupEndpoints(destinationIds: string[]): Map<string, EndpointRow[]> {
    const byDest = new Map<string, EndpointRow[]>();
    for (const ep of this.fetchEndpoints(destinationIds)) {
      const arr = byDest.get(ep.destinationId);
      if (arr) arr.push(ep);
      else byDest.set(ep.destinationId, [ep]);
    }
    return byDest;
  }

  private fetchCallSites(endpointIds: string[]): CallSiteRow[] {
    if (endpointIds.length === 0) return [];
    const rows = allRows<{
      id: string;
      endpointId: string;
      project: string;
      file: string;
      line: number;
      snippet: string;
      dynamic: number;
      vendored: number;
      projectId: string | null;
    }>(
      this.db.prepare(
        `SELECT id, endpoint_id AS endpointId, project, file, line, snippet, dynamic, vendored,
                project_id AS projectId
         FROM share_call_site
         WHERE endpoint_id IN (${placeholders(endpointIds.length)})
         ORDER BY created_at ASC, id ASC`,
      ),
      endpointIds,
    );
    return rows.map((r) => ({
      id: r.id,
      endpointId: r.endpointId,
      project: r.project,
      file: r.file,
      line: r.line,
      snippet: r.snippet,
      dynamic: r.dynamic === 1,
      vendored: r.vendored === 1,
      projectId: r.projectId,
    }));
  }
}
