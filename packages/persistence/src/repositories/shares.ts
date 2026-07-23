import { randomUUID } from 'node:crypto';
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import type {
  CallSite,
  DataClass,
  DestinationKind,
  EgressDecision,
  EgressReconcile,
  EgressWriteSummary,
  EndpointSummary,
  HttpMethod,
  ListShareDestinationsQuery,
  ListShareDestinationsResponse,
  NeedsReviewResponse,
  RecordProjectEgressInput,
  ResolvedEgressHit,
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
import { allRows, boolToInt, countBy, countScalar, getRow } from '../internal/rows.ts';
import { containsPattern, escapeLikePattern, placeholders } from '../internal/sql-text.ts';
import { withTransaction } from '../internal/transactions.ts';
import type { SharesReadPort } from '../ports.ts';

/**
 * Upper bound on the call sites one write records for a project. Hits past it
 * are dropped in input order and the write reports `truncated: true`, so a
 * runaway project is capped visibly instead of silently. Where the drop lands —
 * mid-file or on a file boundary — depends on the reconcile mode; see capHits.
 */
export const MAX_EGRESS_CALL_SITES_PER_PROJECT = 5000;

/** Bind variables per `IN (…)` delete; longer file lists are split across statements. */
const IN_CHUNK = 500;

// Section order for the grouped listing — provider → internal → external → ip.
// A kind missing here is dropped from the response, not just left unlabelled.
const KIND_ORDER: DestinationKind[] = ['provider', 'internal', 'external', 'ip'];

// Transports that carry data without TLS. Mirrors deriveReviewReasons'
// plaintext rule in @akasecurity/schema, which these SQL pre-filters must agree
// with; `wss` and `https` are secure and excluded.
const PLAINTEXT_TRANSPORT_SQL = "('http', 'ws')";

// Host-first override resolution: `oh` re-attaches a decision by host, so it
// survives a destination being pruned and re-detected under a fresh id; `ol`
// matches rows written before the host column existed. Paired with
// COALESCE(oh.decision, ol.decision).
const OVERRIDE_JOIN = `LEFT JOIN egress_decision_override oh ON oh.host = d.host
             LEFT JOIN egress_decision_override ol ON ol.destination_id = d.id AND ol.host IS NULL`;

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

/**
 * Apply MAX_EGRESS_CALL_SITES_PER_PROJECT to one write's hits.
 *
 * Walk mode slices flat: it re-derives the project's whole hit set on every run
 * and keeps no ledger, so the hits past the cap come back next scan and the
 * first ones are the useful ones to keep.
 *
 * Ledger mode cuts at a FILE boundary instead, because there the delete set and
 * the ledger are both named per file. A file is wholly recorded or wholly
 * dropped, and a dropped one is reported so the caller can leave its rows in
 * place and refuse to ledger it. A single file whose own hits exceed the cap is
 * dropped rather than half-kept: half a generated blob's destinations is not a
 * usable inventory of it, and storing it would ledger the file as done.
 */
function capHits(
  all: readonly ResolvedEgressHit[],
  mode: EgressReconcile['mode'],
): { hits: ResolvedEgressHit[]; droppedFiles: string[]; truncated: boolean } {
  if (all.length <= MAX_EGRESS_CALL_SITES_PER_PROJECT) {
    return { hits: [...all], droppedFiles: [], truncated: false };
  }
  if (mode === 'walk') {
    return {
      hits: all.slice(0, MAX_EGRESS_CALL_SITES_PER_PROJECT),
      droppedFiles: [],
      truncated: true,
    };
  }

  const byFile = new Map<string, ResolvedEgressHit[]>();
  for (const hit of all) {
    const bucket = byFile.get(hit.site.file);
    if (bucket === undefined) byFile.set(hit.site.file, [hit]);
    else bucket.push(hit);
  }

  const hits: ResolvedEgressHit[] = [];
  const droppedFiles: string[] = [];
  for (const [file, bucket] of byFile) {
    if (hits.length + bucket.length > MAX_EGRESS_CALL_SITES_PER_PROJECT) droppedFiles.push(file);
    else hits.push(...bucket);
  }
  return { hits, droppedFiles, truncated: true };
}

/**
 * Take the dropped files back out of a ledger-mode reconcile set, so the write
 * neither deletes nor re-creates their rows. Walk mode names no files — it
 * deletes by path prefix and recomputes the whole subtree every run — so it is
 * returned unchanged and its truncation stays a plain per-write cap.
 */
function withoutDroppedFiles(
  reconcile: EgressReconcile,
  droppedFiles: readonly string[],
): EgressReconcile {
  if (reconcile.mode === 'walk' || droppedFiles.length === 0) return reconcile;
  const dropped = new Set(droppedFiles);
  return {
    mode: 'ledger',
    scannedFiles: reconcile.scannedFiles.filter((file) => !dropped.has(file)),
    deletedFiles: reconcile.deletedFiles.filter((file) => !dropped.has(file)),
  };
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
      `SELECT count(DISTINCT destination_id) AS n FROM share_endpoint
       WHERE transport IN ${PLAINTEXT_TRANSPORT_SQL}`,
    );
    const needsReview = countScalar(
      this.db,
      `SELECT count(DISTINCT d.id) AS n
       FROM share_destination d
       LEFT JOIN share_endpoint e ON e.destination_id = d.id
         AND e.transport IN ${PLAINTEXT_TRANSPORT_SQL}
       WHERE d.trust IN ('unverified', 'ip') OR e.id IS NOT NULL`,
    );

    const kindCounts = countBy(
      this.db,
      'SELECT kind AS k, count(*) AS n FROM share_destination GROUP BY kind',
    );
    const byKind: SharesStats['byKind'] = {
      provider: kindCounts.get('provider') ?? 0,
      internal: kindCounts.get('internal') ?? 0,
      external: kindCounts.get('external') ?? 0,
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
   * `null` deletes the override rows → reverts to the trust default.
   *
   * The written row carries both the destination id and its host, so the
   * decision re-attaches by host after the destination is pruned and
   * re-detected under a fresh id. Rows written before the host column existed
   * (host NULL, matched by destination id) are replaced rather than left to
   * shadow the new one. Runs IMMEDIATE: the host lookup is read-then-write and
   * would otherwise race a concurrent prune.
   */
  setEgressDecision(destinationId: string, decision: EgressDecision | null): boolean {
    let existed = false;
    withTransaction(
      this.db,
      () => {
        const dest = this.db
          .prepare('SELECT host FROM share_destination WHERE id = ?')
          .get(destinationId) as { host: string } | undefined;
        if (dest === undefined) return;
        existed = true;

        this.db
          .prepare(
            `DELETE FROM egress_decision_override
             WHERE host = :host OR (destination_id = :destinationId AND host IS NULL)`,
          )
          .run({ host: dest.host, destinationId });
        if (decision === null) return;

        this.db
          .prepare(
            `INSERT INTO egress_decision_override
               (id, destination_id, host, decision, created_at, updated_at)
             VALUES (:id, :destinationId, :host, :decision, :now, :now)`,
          )
          .run({
            id: randomUUID(),
            destinationId,
            host: dest.host,
            decision,
            now: Date.now(),
          });
      },
      'IMMEDIATE',
    );
    return existed;
  }

  /**
   * Record one project's statically-extracted egress: reconcile the previously
   * stored call sites against this scan, upsert destination → endpoint → call
   * site for every hit, confirm `last_seen` on everything the project still
   * references, and drop what no longer has evidence.
   *
   * Reconciliation keys on `projectKey` alone; `project` and `projectId` are
   * display payload and never scope a delete. The whole write is one
   * transaction: a failure leaves the project's previous inventory exactly as
   * it was, and THROWS rather than reporting a partial write — callers decide
   * their own fail-open behavior, and the scanner additionally withholds its
   * ledger commit so the next scan retries.
   *
   * Over-cap input is truncated at a FILE boundary, and the files that lost
   * their hits are both excluded from the reconcile delete and named in
   * `droppedFiles`. That pairing is what keeps truncation non-destructive on
   * the ledger path: a dropped file keeps whatever rows it already had, and its
   * caller withholds the ledger entry so the next scan reads it again.
   */
  recordProjectEgress(input: RecordProjectEgressInput): EgressWriteSummary {
    const { hits, droppedFiles, truncated } = capHits(input.hits, input.reconcile.mode);
    const reconcile = withoutDroppedFiles(input.reconcile, droppedFiles);
    const now = Date.now();

    let summary: EgressWriteSummary = {
      destinations: 0,
      endpoints: 0,
      callSites: 0,
      truncated,
      droppedFiles,
    };
    withTransaction(
      this.db,
      () => {
        // Read BEFORE the reconcile delete: ledger mode deletes the rows it is
        // about to re-insert, so a project id carried only by those rows would
        // be gone by the time the insert needs it.
        const projectId = input.projectId ?? this.knownProjectId(input.projectKey);
        this.reconcileCallSites(input.projectKey, reconcile);
        this.upsertHits(input, hits, projectId, now);
        this.confirmLastSeen(input.projectKey, now);
        this.pruneOrphans();
        summary = { ...this.projectTotals(input.projectKey), truncated, droppedFiles };
      },
      'IMMEDIATE',
    );
    return summary;
  }

  // ─── Egress write internals ──────────────────────────────────────────────────

  /**
   * Clear the stored call sites this scan is responsible for re-creating.
   *
   * Each pipeline may only delete rows its own walker could have produced. The
   * fs walk behind 'walk' mode never descends into dot-directories, so its
   * delete excludes dot-path files — those rows are the plugin scanner's to
   * reconcile, and deleting them here would make the two pipelines erase each
   * other's rows on every alternating scan. 'ledger' mode names its files
   * outright and never mass-deletes, so rows the fs walk contributed for files
   * the scanner skips (vendored, oversize) survive it.
   */
  private reconcileCallSites(projectKey: string, reconcile: EgressReconcile): void {
    if (reconcile.mode === 'walk') {
      const prefix = reconcile.walkedPrefix.replace(/\/+$/, '');
      this.db
        .prepare(
          `DELETE FROM share_call_site
           WHERE project_key = :key
             AND (:prefix = '' OR file = :prefix OR file LIKE :subtree ESCAPE '\\')
             AND file NOT LIKE '.%'
             AND file NOT LIKE '%/.%'`,
        )
        // The prefix is a path, so '_' and '%' in a directory name must match
        // literally rather than as LIKE wildcards over a sibling directory.
        .run({ key: projectKey, prefix, subtree: `${escapeLikePattern(prefix)}/%` });
      return;
    }

    const files = [...new Set([...reconcile.scannedFiles, ...reconcile.deletedFiles])];
    for (let i = 0; i < files.length; i += IN_CHUNK) {
      const chunk = files.slice(i, i + IN_CHUNK);
      this.db
        .prepare(
          `DELETE FROM share_call_site
           WHERE project_key = ? AND file IN (${placeholders(chunk.length)})`,
        )
        .run(projectKey, ...chunk);
    }
  }

  /**
   * Upsert every hit as destination → endpoint → call site. Destinations key on
   * `host` and endpoints on `(destination_id, method, url)`, both shared across
   * projects; only the call site carries `project_key`. A destination's `note`
   * is user-owned and never overwritten. The id caches keep one upsert per
   * distinct host and endpoint, so the first hit for a host supplies its
   * classification for this batch.
   */
  private upsertHits(
    input: RecordProjectEgressInput,
    hits: ResolvedEgressHit[],
    projectId: string | null,
    now: number,
  ): void {
    if (hits.length === 0) return;

    const destStmt = this.db.prepare(
      `INSERT INTO share_destination
         (id, kind, name, host, category, trust, network_json, last_seen, provenance,
          created_at, updated_at)
       VALUES (:id, :kind, :name, :host, :category, :trust, :networkJson, :now, 'scan', :now, :now)
       ON CONFLICT (host) DO UPDATE SET
         kind = excluded.kind,
         name = excluded.name,
         category = excluded.category,
         trust = excluded.trust,
         network_json = excluded.network_json,
         last_seen = excluded.last_seen,
         updated_at = excluded.updated_at`,
    );
    const destIdStmt = this.db.prepare('SELECT id FROM share_destination WHERE host = ?');
    const endpointStmt = this.db.prepare(
      `INSERT INTO share_endpoint
         (id, destination_id, method, transport, url, template, data_class, last_seen,
          created_at, updated_at)
       VALUES (:id, :destinationId, :method, :transport, :url, :template, :dataClass, :now,
               :now, :now)
       ON CONFLICT (destination_id, method, url) DO UPDATE SET
         transport = excluded.transport,
         template = excluded.template,
         data_class = excluded.data_class,
         last_seen = excluded.last_seen,
         updated_at = excluded.updated_at`,
    );
    const endpointIdStmt = this.db.prepare(
      'SELECT id FROM share_endpoint WHERE destination_id = ? AND method = ? AND url = ?',
    );
    // ON CONFLICT, not a plain INSERT: two hits can land on the same endpoint,
    // file and line, and a UNIQUE failure would abort the whole scan's egress.
    //
    // `project_id` is COALESCEd rather than overwritten so a row this write did
    // not delete keeps its link when no id could be resolved at all.
    const siteStmt = this.db.prepare(
      `INSERT INTO share_call_site
         (id, endpoint_id, project, project_key, file, line, snippet, dynamic, vendored,
          project_id, created_at, updated_at)
       VALUES (:id, :endpointId, :project, :projectKey, :file, :line, :snippet, :dynamic,
               :vendored, :projectId, :now, :now)
       ON CONFLICT (endpoint_id, project_key, file, line) DO UPDATE SET
         snippet = excluded.snippet,
         dynamic = excluded.dynamic,
         vendored = excluded.vendored,
         project = excluded.project,
         project_id = COALESCE(excluded.project_id, share_call_site.project_id),
         updated_at = excluded.updated_at`,
    );

    const destIds = new Map<string, string>();
    const endpointIds = new Map<string, string>();

    for (const hit of hits) {
      let destinationId = destIds.get(hit.host);
      if (destinationId === undefined) {
        destStmt.run({
          id: randomUUID(),
          kind: hit.kind,
          name: hit.name,
          host: hit.host,
          category: hit.category,
          trust: hit.trust,
          networkJson: hit.network === null ? null : JSON.stringify(hit.network),
          now,
        });
        destinationId = getRow<{ id: string }>(destIdStmt, [hit.host])?.id ?? '';
        destIds.set(hit.host, destinationId);
      }

      const endpointKey = `${destinationId}\x00${hit.method}\x00${hit.url}`;
      let endpointId = endpointIds.get(endpointKey);
      if (endpointId === undefined) {
        endpointStmt.run({
          id: randomUUID(),
          destinationId,
          method: hit.method,
          transport: hit.transport,
          url: hit.url,
          template: boolToInt(hit.template),
          dataClass: hit.dataClass,
          now,
        });
        endpointId =
          getRow<{ id: string }>(endpointIdStmt, [destinationId, hit.method, hit.url])?.id ?? '';
        endpointIds.set(endpointKey, endpointId);
      }

      siteStmt.run({
        id: randomUUID(),
        endpointId,
        project: input.project,
        projectKey: input.projectKey,
        file: hit.site.file,
        line: hit.site.line,
        snippet: hit.site.snippet,
        dynamic: boolToInt(hit.site.dynamic),
        vendored: boolToInt(hit.site.vendored),
        projectId,
        now,
      });
    }
  }

  /**
   * The source-project id this project's stored call sites already carry, if
   * any. Only the pipeline that resolves a source project supplies one; the
   * other passes null and inherits this, so the link stops flapping between a
   * real id and NULL depending on which pipeline ran last. The value is a
   * per-project attribute stored redundantly on each row, so any row's is
   * representative.
   */
  private knownProjectId(projectKey: string): string | null {
    return (
      getRow<{ projectId: string | null }>(
        this.db.prepare(
          `SELECT project_id AS projectId FROM share_call_site
           WHERE project_key = ? AND project_id IS NOT NULL LIMIT 1`,
        ),
        [projectKey],
      )?.projectId ?? null
    );
  }

  /**
   * Stamp `last_seen` on every endpoint and destination this project still
   * references — including rows the scan preserved rather than re-wrote, so a
   * ledger-skipped file's references don't decay into "stale" on the page.
   */
  private confirmLastSeen(projectKey: string, now: number): void {
    this.db
      .prepare(
        `UPDATE share_endpoint SET last_seen = :now, updated_at = :now
         WHERE id IN (SELECT DISTINCT endpoint_id FROM share_call_site WHERE project_key = :key)`,
      )
      .run({ now, key: projectKey });
    this.db
      .prepare(
        `UPDATE share_destination SET last_seen = :now, updated_at = :now
         WHERE id IN (SELECT DISTINCT e.destination_id
                      FROM share_endpoint e
                      JOIN share_call_site c ON c.endpoint_id = e.id
                      WHERE c.project_key = :key)`,
      )
      .run({ now, key: projectKey });
  }

  /**
   * Drop rows left without evidence: endpoints with no call site, then
   * destinations with no endpoint. Call sites are the only evidence either one
   * has, so a row that lost its last one belongs to no project any more.
   *
   * Overrides are deleted between the two steps, and only the ones written
   * before the host column existed. Those match a destination by id alone;
   * because the id link is released on delete rather than cascading, leaving
   * them would accumulate rows that match neither join arm and that nothing can
   * reach again. Host-bearing rows deliberately survive — the host is what
   * re-attaches a user's decision when the destination comes back.
   */
  private pruneOrphans(): void {
    this.db.exec(
      `DELETE FROM share_endpoint
       WHERE NOT EXISTS (SELECT 1 FROM share_call_site c WHERE c.endpoint_id = share_endpoint.id)`,
    );
    this.db.exec(
      `DELETE FROM egress_decision_override
       WHERE host IS NULL
         AND destination_id IN (
           SELECT d.id FROM share_destination d
           WHERE NOT EXISTS (SELECT 1 FROM share_endpoint e WHERE e.destination_id = d.id))`,
    );
    this.db.exec(
      `DELETE FROM share_destination
       WHERE NOT EXISTS (
         SELECT 1 FROM share_endpoint e WHERE e.destination_id = share_destination.id)`,
    );
  }

  /**
   * Live totals for one project. Destinations and endpoints are shared across
   * projects and carry no project column, so both are counted through the call
   * sites that reference them.
   */
  private projectTotals(
    projectKey: string,
  ): Omit<EgressWriteSummary, 'truncated' | 'droppedFiles'> {
    return {
      destinations: countScalar(
        this.db,
        `SELECT count(DISTINCT e.destination_id) AS n
         FROM share_endpoint e
         JOIN share_call_site c ON c.endpoint_id = e.id
         WHERE c.project_key = ?`,
        [projectKey],
      ),
      endpoints: countScalar(
        this.db,
        'SELECT count(DISTINCT endpoint_id) AS n FROM share_call_site WHERE project_key = ?',
        [projectKey],
      ),
      callSites: countScalar(
        this.db,
        'SELECT count(*) AS n FROM share_call_site WHERE project_key = ?',
        [projectKey],
      ),
    };
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
                  d.created_at AS createdAt,
                  COALESCE(oh.decision, ol.decision) AS overrideDecision`;
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
                     WHERE re.destination_id = d.id
                       AND re.transport IN ${PLAINTEXT_TRANSPORT_SQL}))`,
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
             ${OVERRIDE_JOIN}
             LEFT JOIN share_endpoint e ON e.destination_id = d.id
             LEFT JOIN share_call_site c ON c.endpoint_id = e.id
             ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''}
             ORDER BY d.created_at ASC, d.id ASC`;
    } else {
      sql = `SELECT ${cols}
             FROM share_destination d
             ${OVERRIDE_JOIN}
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
                COALESCE(oh.decision, ol.decision) AS overrideDecision
         FROM share_destination d
         ${OVERRIDE_JOIN}
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
