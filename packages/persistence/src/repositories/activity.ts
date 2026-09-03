import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import type {
  ActivitySession,
  ActivitySessionSummary,
  AuditEvent,
  AuditEventKind,
  GetActivityStatsResponse,
  Harness as HarnessType,
  ListActivitySessionsQuery,
  ListActivitySessionsResponse,
  LlmCallAttributes,
  LlmCallLeaf,
  SessionStatus as SessionStatusType,
  SessionTokenReport,
  TokenRollup,
} from '@akasecurity/schema';
import {
  ActivityLink,
  buildTokenReports,
  defaultCostModel,
  epochMillisToIso,
  eventSeverity,
  HARNESS,
  Harness,
  isoToEpochMillis,
  SessionStatus,
} from '@akasecurity/schema';

import { safeJson } from '../internal/json.ts';
import { decodeKeysetCursor, encodeKeysetCursor } from '../internal/keyset-cursor.ts';
import { allRows, countScalar, getRow, intToBool } from '../internal/rows.ts';
import { containsPattern, placeholders } from '../internal/sql-text.ts';
import type { ActivityReadPort } from '../ports.ts';

const DAY_MS = 86_400_000;

// How long a session may sit idle (no new events, still `ended_at IS NULL`)
// before it stops counting as "live". The local store has no session-end writer —
// SessionStart opens the root, but no hook ever stamps `ended_at` (the Stop hook
// only spawns the reconciler) — so EVERY session would otherwise stay `active`
// forever and "Live now" would climb to the store's entire session history. A
// session is therefore live only while its most recent activity is within this
// window; older open sessions are reported `completed` at their last-activity
// time. 30 min comfortably covers a session paused mid-task while dropping the
// long tail of never-closed roots.
export const LIVE_ACTIVITY_WINDOW_MS = 30 * 60_000;

// An event's "last activity" is the later of its start and its end
// (`max(started_at, coalesce(ended_at, started_at))`): a long-running tool
// call keeps its session live until it FINISHES, not just when it began. The
// reads below take that maximum as two index seeks — the latest start and the
// latest end under a root — rather than as one expression walked over every
// descendant, which is what it used to be.

// Default IANA zone when the caller omits `tz`: the web-ui server IS the
// user's machine, so its local zone is the right "today" boundary.
function defaultTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return 'UTC';
  }
}

// ---------------------------------------------------------------------------
// Pure helpers — ports of services/activity.ts (the OSS adapter fetches AND
// assembles the finished contract shapes, so the reconstruction logic lives
// here rather than in a separate service).
// ---------------------------------------------------------------------------

interface TodayWindow {
  startMs: number;
  endMs: number;
}

/**
 * Half-open `[start, end)` "today" window in epoch millis for `timeZone` as of
 * `nowMs`. Same algorithm/approximation as services/activity.ts `todayWindowUtc`
 * (offset sampled at `now`, exact except within a DST-transition hour). Fail-open
 * to the default zone on an invalid IANA id — never throws.
 */
export function todayWindow(timeZone: string, nowMs: number): TodayWindow {
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    }).formatToParts(new Date(nowMs));
  } catch {
    const fallback = defaultTimeZone();
    return timeZone === fallback ? utcWindow(nowMs) : todayWindow(fallback, nowMs);
  }

  const byType = Object.fromEntries(parts.map((p) => [p.type, p.value]));
  const year = Number(byType.year);
  const month = Number(byType.month);
  const day = Number(byType.day);
  const hour = Number(byType.hour);
  const minute = Number(byType.minute);
  const second = Number(byType.second);

  const localAsUtcMs = Date.UTC(year, month - 1, day, hour, minute, second);
  const offsetMs = localAsUtcMs - nowMs;
  const localMidnightAsUtcMs = Date.UTC(year, month - 1, day, 0, 0, 0);
  const startMs = localMidnightAsUtcMs - offsetMs;
  return { startMs, endMs: startMs + DAY_MS };
}

// Last-resort UTC window — only reached if even the resolved default zone is
// rejected by Intl (shouldn't happen; UTC never throws).
function utcWindow(nowMs: number): TodayWindow {
  const startMs = Math.floor(nowMs / DAY_MS) * DAY_MS;
  return { startMs, endMs: startMs + DAY_MS };
}

// DB event_type → contract AuditEventKind. `tool_call` renames to `tool`; the
// fixture/seed-only kinds pass through verbatim; the structural rows (`llm_call`/
// `run`/`source_lookup`/`code_change`/`config_scan`) have no timeline kind and
// are dropped from events[]. Same table as services/activity.ts.
const DB_EVENT_TYPE_TO_KIND: Partial<Record<string, AuditEventKind>> = {
  session: 'session',
  prompt: 'prompt',
  response: 'response',
  tool_call: 'tool',
  hook: 'hook',
  detection: 'detection',
  share: 'share',
  permission: 'permission',
  commit: 'commit',
  error: 'error',
  active: 'active',
};

// The SQL form of the map's keys: the timeline read filters to them in the
// statement, because the structural rows it would otherwise fetch and drop
// (every `llm_call`, every `code_change`, every `tool_use`) outnumber the rows
// it renders, and reading them cost the detail pane the whole session per open.
const TIMELINE_EVENT_TYPES = Object.keys(DB_EVENT_TYPE_TO_KIND)
  .map((kind) => `'${kind}'`)
  .join(', ');

/** Parse a JSON-array attribute (branches/models/files), degrading to [] on a
 * missing or malformed value — never throws on a legacy-shaped row. */
function safeParseStringArray(raw: string | null): string[] {
  if (!raw) return [];
  const parsed = safeJson<unknown>(raw, null);
  return Array.isArray(parsed) ? (parsed as string[]) : [];
}

// What a session root with no stored `harness` attribute reads as. Named once
// because three places spell it — this validator and the two SQL coalesces
// below — and a disagreement is silent: the filter would match rows the view
// renders under a different harness. A code-defined constant, never user input,
// so the SQL interpolations are injection-safe.
//
// They agree on the NULL case only, and that is the whole of what is claimed
// here. `toHarness` rescues any value the enum rejects; `coalesce` rescues only
// NULL. So a root stored with an off-enum harness renders as the default and
// appears in the facets under it, while the SQL filter compares its raw stored
// value and matches nothing — the row vanishes when the user selects the very
// harness it is shown as. No writer in this repo produces such a value (every
// handleSessionStart caller passes a mapped tool), which is why this is stated
// rather than fixed; activity.test.ts pins the divergence so that closing it is
// a deliberate edit and not an accident.
const DEFAULT_HARNESS = HARNESS.ClaudeCode;

/** Validate a raw harness attribute against the enum, defaulting to
 * `DEFAULT_HARNESS` so the FE's `PROVIDERS[harness]` lookup can never miss
 * (crash the view). */
function toHarness(raw: string | null): HarnessType {
  const parsed = Harness.safeParse(raw);
  return parsed.success ? parsed.data : DEFAULT_HARNESS;
}

interface SessionRootRow {
  id: string;
  harness: string | null;
  title: string | null;
  project: string | null;
  repo: string | null;
  branches: string | null;
  status: string | null;
  started_at: number;
  ended_at: number | null;
}

interface SessionRollup {
  turns: number;
  findings: number;
  shares: number;
  /** Epoch-ms of the session's most recent descendant event (0 if it has none).
   * Combined with the root's own `started_at` to decide liveness. */
  lastActivityMs: number;
}

/**
 * A session's lifecycle `status` + effective `endedAt`, folding in the idle
 * heuristic. A pinned `attributes.status` (interrupted/error from a seed) wins; a
 * row with a real `ended_at` is `completed`; an open row is `active` only while its
 * last activity is within `LIVE_ACTIVITY_WINDOW_MS`, otherwise it's reported
 * `completed` at that last-activity time (never a perpetual "live"). Never throws.
 */
function resolveLifecycle(
  row: SessionRootRow,
  lastActivityMs: number,
  nowMs: number,
): { status: SessionStatusType; endedAtMs: number | null } {
  if (row.status) {
    const parsed = SessionStatus.safeParse(row.status);
    if (parsed.success) return { status: parsed.data, endedAtMs: row.ended_at };
  }
  if (row.ended_at !== null) return { status: 'completed', endedAtMs: row.ended_at };
  if (lastActivityMs >= nowMs - LIVE_ACTIVITY_WINDOW_MS) {
    return { status: 'active', endedAtMs: null };
  }
  return { status: 'completed', endedAtMs: lastActivityMs };
}

// A never-blank session title: the stored `content`, else the project, else the
// repo, else a short session-id stub — so a session root written without a title
// (the live capture path stores no title) still reads as something meaningful in
// the list/detail instead of an empty row. Real capture now stamps project/repo
// on the root; this also rescues pre-enrichment rows via the same fallbacks.
function resolveTitle(row: SessionRootRow): string {
  // `||` (not `??`) is deliberate: `content`/`project`/`repo` come back as EMPTY
  // strings (not just null) for a bare root, and an empty candidate must fall
  // through to the next — `??` would stop at the first empty string.
  // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
  return row.title || row.project || row.repo || `Session ${row.id.slice(0, 8)}`;
}

function toSummary(
  row: SessionRootRow,
  rollup: SessionRollup,
  nowMs: number,
): ActivitySessionSummary {
  const lastActivityMs = Math.max(row.started_at, rollup.lastActivityMs);
  const { status, endedAtMs } = resolveLifecycle(row, lastActivityMs, nowMs);
  return {
    id: row.id,
    harness: toHarness(row.harness),
    title: resolveTitle(row),
    project: row.project ?? '',
    repo: row.repo ?? '',
    branches: safeParseStringArray(row.branches),
    startedAt: epochMillisToIso(row.started_at),
    endedAt: endedAtMs === null ? null : epochMillisToIso(endedAtMs),
    status,
    turns: rollup.turns,
    findings: rollup.findings,
    shares: rollup.shares,
  };
}

interface TimelineRow {
  id: string;
  event_type: string;
  started_at: number;
  title: string | null;
  detail: string | null;
  tool: string | null;
  severity: string | null;
  link: string | null;
  target_id: string | null;
  internal: number | null;
  flagged: number | null;
}

/** Map one raw timeline row onto the contract AuditEvent, or null when its
 * event_type has no timeline kind (structural rows). severity/link fall back to
 * null on an out-of-enum value — never throws on a malformed attribute. */
function buildAuditEvent(row: TimelineRow): AuditEvent | null {
  const kind = DB_EVENT_TYPE_TO_KIND[row.event_type];
  if (!kind) return null;

  const severityParsed = row.severity ? eventSeverity.safeParse(row.severity) : null;
  const linkParsed = row.link ? ActivityLink.safeParse(row.link) : null;

  return {
    id: row.id,
    occurredAt: epochMillisToIso(row.started_at),
    kind,
    title: row.title ?? '',
    detail: row.detail ?? '',
    tool: row.tool,
    severity: severityParsed?.success ? severityParsed.data : null,
    link: linkParsed?.success ? linkParsed.data : null,
    targetId: row.target_id,
    internal: intToBool(row.internal),
    flagged: intToBool(row.flagged),
  };
}

// Column projection shared by the timeline reads. `tool`/`title`/`detail`
// coalesce the reconciler's real attribute names onto the display fields so a
// `tool_call` leaf reads well on the timeline: `tool_name` is the canonical
// schema field (the fixtures' legacy `tool` key is the fallback), the tool name
// stands in as the event title when no `content` was written, and the masked
// `target` (the WebFetch url / Bash command) stands in as the detail.
const TIMELINE_COLUMNS = `
  id,
  event_type,
  started_at,
  coalesce(content, json_extract(attributes, '$.tool_name')) AS title,
  coalesce(json_extract(attributes, '$.detail'), json_extract(attributes, '$.target')) AS detail,
  coalesce(json_extract(attributes, '$.tool_name'), json_extract(attributes, '$.tool')) AS tool,
  json_extract(attributes, '$.severity') AS severity,
  json_extract(attributes, '$.link') AS link,
  json_extract(attributes, '$.targetId') AS target_id,
  json_extract(attributes, '$.internal') AS internal,
  json_extract(attributes, '$.flagged') AS flagged`;

/**
 * One `llm_call` group: every call in one session on one
 * `(provider, model, service_tier)`, with its usage members summed. The grain
 * is the one PRICING needs, not the one the view renders: `CostModel.costFor`
 * is linear in each usage member and applies the service-tier multiplier to
 * the token subtotal, so summing within a fixed `(provider, model, tier)` and
 * pricing ONCE gives the figure that pricing every call and adding would. The
 * tier is in the key precisely because it is the one per-call dimension that
 * changes the multiplier, and the 1h/5m cache-write split rides along as two
 * sums because the two are priced apart. That exactness is what lets the
 * report collapse in SQL over the usage index instead of shipping one bag per
 * call to JS — activity.test.ts holds the two folds equal across every shape a
 * bag takes, and token-rollup-plans.test.ts pins the index.
 */
interface LlmUsageRow {
  sessionId: string;
  provider: string | null;
  model: string | null;
  serviceTier: string | null;
  inputTokens: number;
  outputTokens: number;
  cacheCreationTokens: number;
  cacheReadTokens: number;
  ephemeral1hTokens: number;
  ephemeral5mTokens: number;
  webSearchRequests: number;
}

const LLM_USAGE_SELECT = `
  SELECT root_session_id AS sessionId,
         provider,
         model,
         service_tier AS serviceTier,
         coalesce(sum(input_tokens), 0) AS inputTokens,
         coalesce(sum(output_tokens), 0) AS outputTokens,
         coalesce(sum(cache_creation_input_tokens), 0) AS cacheCreationTokens,
         coalesce(sum(cache_read_input_tokens), 0) AS cacheReadTokens,
         coalesce(sum(ephemeral_1h_input_tokens), 0) AS ephemeral1hTokens,
         coalesce(sum(ephemeral_5m_input_tokens), 0) AS ephemeral5mTokens,
         coalesce(sum(web_search_requests), 0) AS webSearchRequests`;

// The usage index's own predicate (`idx_audit_llm_usage` is partial on exactly
// these two terms), so the index applies and neither is re-checked against the
// row: a call with no bag has no usage to roll up, and a leaf with no root
// session cannot be attributed. A bag that is not JSON cannot be inserted at
// all — the store's expression indexes reject it at write — so there is no
// unparseable leaf to skip, and a generated column only ever reads a valid bag.
const LLM_USAGE_SCOPE = `event_type = 'llm_call' AND attributes IS NOT NULL AND root_session_id IS NOT NULL`;

const LLM_USAGE_GROUP = `GROUP BY root_session_id, provider, model, service_tier`;

/** The grouped rows as synthetic leaves — exact by the cost model's linearity (see LlmUsageRow). */
function usageLeaves(rows: readonly LlmUsageRow[]): LlmCallLeaf[] {
  return rows.map((row) => {
    const attributes: LlmCallAttributes = {
      input_tokens: row.inputTokens,
      output_tokens: row.outputTokens,
      cache_creation_input_tokens: row.cacheCreationTokens,
      cache_read_input_tokens: row.cacheReadTokens,
      ephemeral_1h_input_tokens: row.ephemeral1hTokens,
      ephemeral_5m_input_tokens: row.ephemeral5mTokens,
      web_search_requests: row.webSearchRequests,
    };
    // Set only when the group has one: exactOptionalPropertyTypes tells an
    // absent key from an undefined one, and buildTokenReports reads an absent
    // provider or model as 'unknown' and an absent tier as 1x — exactly what a
    // bag without them meant when every call was folded on its own.
    if (row.provider !== null) attributes.provider = row.provider;
    if (row.model !== null) attributes.model = row.model;
    if (row.serviceTier !== null) attributes.service_tier = row.serviceTier;
    return { sessionId: row.sessionId, attributes };
  });
}

// A session root row. EVERY `event_type='session'` row counts, and a row missing
// the fixture/live attributes degrades to defensive defaults (see
// `toHarness`/`toSummary`) rather than being hidden — so dashboards render
// identically for bare session rows too, not just for fully-attributed seed data.
const SESSION_ROOT = `event_type = 'session'`;

// A session root "has activity" when any child event is more than bookkeeping —
// hooks and config scans are recorded for every launch (including background
// `claude` invocations that never see a prompt), so they alone don't make a
// session worth listing. Correlates on the outer `audit_events` row; served by
// idx_audit_session (root_session_id, started_at).
const HAS_ACTIVITY = `EXISTS (
  SELECT 1 FROM audit_events c
  WHERE c.root_session_id = audit_events.id
    AND c.event_type NOT IN ('hook', 'config_scan'))`;

/**
 * Activity read views over the local `audit_events` store. Runs the
 * session/timeline queries on node:sqlite (epoch-ms integer columns,
 * `json_extract` attribute reads, the generated token columns), assembling the
 * finished @akasecurity/schema responses — the local store IS the activity service.
 * The clock is injectable so the "today" window and live-duration are
 * deterministic under test.
 */
export class SqliteActivityRepository implements ActivityReadPort {
  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => number = () => Date.now(),
  ) {}

  stats(tz?: string): Promise<GetActivityStatsResponse> {
    const window = todayWindow(tz ?? defaultTimeZone(), this.now());
    const { startMs, endMs } = window;

    // Only sessions with real activity — background `claude` launches record a
    // root (plus hook/config-scan bookkeeping) and nothing else, and would
    // otherwise dominate the count on stores where they outnumber real work.
    const sessionsToday = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events
           WHERE ${SESSION_ROOT} AND started_at >= ? AND started_at < ?
             AND ${HAS_ACTIVITY}`,
      [startMs, endMs],
    );

    // liveNow — open sessions still recently active (tz-independent, no day
    // boundary). "Open" alone is not enough: the local store never stamps
    // `ended_at` on the root, so a bare `ended_at IS NULL` count would return the
    // entire session history. A session is live only while its most recent
    // activity is inside LIVE_ACTIVITY_WINDOW_MS, and "most recent activity"
    // folds in each descendant's OWN `ended_at`, so a single long-running event
    // — a subagent, a build, a 35-min tool call — keeps the session live off
    // its end time, not its start.
    //
    // Driven from the rows active in the window, not from the open roots: a
    // root is live iff it started in the window, or a descendant started in
    // it, or a descendant ended in it — three index ranges, and the outer
    // query seeks each root the list names by primary key — so the read costs
    // the last thirty minutes of the store and nothing else. The per-root
    // form it replaces (`max(...)` over every descendant of every open root)
    // read the whole table, because on a real store EVERY root is open.
    //
    // Three `INDEXED BY`s, all deliberate, none of which the planner takes on
    // its own (the store never runs ANALYZE, so it prices from the schema).
    // The two descendant ranges: each column is also the second column of a
    // (root_session_id, …) index, and the planner prefers a skip-scan over
    // every root through that one, which is the per-root walk again (2.8 ms
    // against 0.1 ms at 200k captures for the start range). The outer: left
    // to itself it enumerates every session root through an event-type-led
    // index and tests each against the list, linear in roots (4.8x across a
    // ten-fold store), where the list — the last thirty minutes — is tiny and
    // constant; seeking it by primary key is flat (1.2x) and six times
    // cheaper. `sqlite_autoindex_audit_events_1` is SQLite's implicit name
    // for the primary key's index, stable while `id` stays the table's only
    // primary key and its first autoindex — the timeline probe asserts the
    // same name. The indexes named are ones every open store carries, since
    // opening runs the migrations, so the hard requirement `INDEXED BY`
    // introduces is already met; activity-probe-plans.test.ts pins the plan.
    const liveThreshold = this.now() - LIVE_ACTIVITY_WINDOW_MS;
    const liveNow = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events s INDEXED BY sqlite_autoindex_audit_events_1
           WHERE s.event_type = 'session' AND s.ended_at IS NULL
             AND s.id IN (
               SELECT id FROM audit_events WHERE event_type = 'session' AND started_at >= ?
               UNION
               SELECT root_session_id FROM audit_events INDEXED BY idx_audit_started_at
                WHERE started_at >= ?
               UNION
               SELECT root_session_id FROM audit_events INDEXED BY idx_audit_ended_at
                WHERE ended_at >= ?)`,
      [liveThreshold, liveThreshold, liveThreshold],
    );

    const toolCallsToday = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events
           WHERE event_type = 'tool_call' AND started_at >= ? AND started_at < ?`,
      [startMs, endMs],
    );

    // Counts inspection_findings ONLY (transcript- and scan-derived rows keyed
    // to audit_events). Live-capture findings are a separate store
    // (findings ⋈ events) surfaced by the security views (severitySummary,
    // healthSummary, listGroupedFindings) — the two are deliberately NOT summed
    // here: the same secret can be recorded in both (enforced live at the hook,
    // then re-detected in the persisted transcript), so a naive union would
    // double-count it. The Activity page's number is therefore narrower than
    // the security pages' by design.
    const findingsToday = countScalar(
      this.db,
      `SELECT count(*) AS n FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
           WHERE e.started_at >= ? AND e.started_at < ?`,
      [startMs, endMs],
    );

    const egressToday = countScalar(
      this.db,
      `SELECT count(DISTINCT json_extract(attributes, '$.destination')) AS n
           FROM audit_events
           WHERE event_type = 'share' AND started_at >= ? AND started_at < ?`,
      [startMs, endMs],
    );

    return Promise.resolve({ sessionsToday, liveNow, toolCallsToday, findingsToday, egressToday });
  }

  listSessions(query: ListActivitySessionsQuery): Promise<ListActivitySessionsResponse> {
    const cursor = query.cursor ? decodeKeysetCursor(query.cursor) : null;
    const toMs = query.to ? isoToEpochMillis(query.to) : this.now();
    const fromMs = query.from ? isoToEpochMillis(query.from) : undefined;

    const conditions: string[] = [SESSION_ROOT];
    const params: unknown[] = [];

    if (query.harness && query.harness.length > 0) {
      // Coalesce the stored harness to the SAME default the read side applies
      // (`toHarness` → DEFAULT_HARNESS). The live capture path historically
      // wrote no `harness` attribute, so a bare `$.harness IN (...)` matched zero
      // rows — filtering by the default returned nothing even though every bare
      // row RENDERS as it. Coalescing makes the filter agree with the view.
      conditions.push(
        `coalesce(json_extract(attributes, '$.harness'), '${DEFAULT_HARNESS}') IN (${placeholders(query.harness.length)})`,
      );
      params.push(...query.harness);
    }
    if (fromMs !== undefined) {
      conditions.push('started_at >= ?');
      params.push(fromMs);
    }
    conditions.push('started_at <= ?');
    params.push(toMs);

    if (query.q) {
      const pattern = containsPattern(query.q);
      conditions.push(
        `(content LIKE ? ESCAPE '\\'
          OR json_extract(attributes, '$.project') LIKE ? ESCAPE '\\'
          OR json_extract(attributes, '$.repo') LIKE ? ESCAPE '\\'
          OR json_extract(attributes, '$.branches') LIKE ? ESCAPE '\\'
          OR EXISTS (
            SELECT 1 FROM audit_events d
            WHERE d.root_session_id = audit_events.id
              AND (d.content LIKE ? ESCAPE '\\'
                   OR json_extract(d.attributes, '$.detail') LIKE ? ESCAPE '\\')))`,
      );
      params.push(pattern, pattern, pattern, pattern, pattern, pattern);
    }
    // Zero-activity sessions matching the filters so far (range/harness/q, no
    // cursor — the count is page-independent). Always reported, so the UI's
    // collapse toggle can label itself; the page itself drops them only when
    // the query says so. This second scan doubles the q-search predicate's
    // cost when a q is set — accepted: searches are debounced and the count
    // must honor the same filters the list does.
    const emptyCount = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events
        WHERE ${[...conditions, `NOT ${HAS_ACTIVITY}`].join(' AND ')}`,
      params as SQLInputValue[],
    );
    if (query.excludeEmpty) conditions.push(HAS_ACTIVITY);

    if (cursor) {
      // Keyset pagination, expanded tuple comparison (node:sqlite has no row-
      // value syntax): strictly-earlier startedAt, or same startedAt + lower id.
      conditions.push('(started_at < ? OR (started_at = ? AND id < ?))');
      params.push(cursor.startedAtMs, cursor.startedAtMs, cursor.id);
    }

    // Fetch one extra row to detect a next page without a separate COUNT.
    const limit = query.limit;
    const rows = allRows<SessionRootRow>(
      this.db.prepare(
        `SELECT id,
                json_extract(attributes, '$.harness') AS harness,
                content AS title,
                json_extract(attributes, '$.project') AS project,
                json_extract(attributes, '$.repo') AS repo,
                json_extract(attributes, '$.branches') AS branches,
                json_extract(attributes, '$.status') AS status,
                started_at,
                ended_at
         FROM audit_events
         WHERE ${conditions.join(' AND ')}
         ORDER BY started_at DESC, id DESC
         LIMIT ?`,
      ),
      [...(params as SQLInputValue[]), limit + 1],
    );

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;

    const rollups = this.rollupsFor(page.map((r) => r.id));
    const now = this.now();
    const items = page.map((r) =>
      toSummary(
        r,
        rollups.get(r.id) ?? { turns: 0, findings: 0, shares: 0, lastActivityMs: 0 },
        now,
      ),
    );

    const last = page[page.length - 1];
    const nextCursor =
      hasMore && last ? encodeKeysetCursor({ startedAtMs: last.started_at, id: last.id }) : null;

    return Promise.resolve({ items, nextCursor, emptyCount });
  }

  getSession(sessionId: string): Promise<ActivitySession | null> {
    const rootRow = getRow<
      SessionRootRow & {
        host: string | null;
        cwd: string | null;
        models: string | null;
        version: string | null;
        files: string | null;
      }
    >(
      this.db.prepare(
        `SELECT id,
                json_extract(attributes, '$.harness') AS harness,
                content AS title,
                json_extract(attributes, '$.project') AS project,
                json_extract(attributes, '$.repo') AS repo,
                json_extract(attributes, '$.branches') AS branches,
                json_extract(attributes, '$.status') AS status,
                json_extract(attributes, '$.host') AS host,
                json_extract(attributes, '$.cwd') AS cwd,
                json_extract(attributes, '$.models') AS models,
                json_extract(attributes, '$.version') AS version,
                json_extract(attributes, '$.files') AS files,
                started_at,
                ended_at
         FROM audit_events
         WHERE id = ? AND event_type = 'session'
         LIMIT 1`,
      ),
      [sessionId],
    );

    if (!rootRow) return Promise.resolve(null);

    const timelineRows = allRows<TimelineRow>(
      this.db.prepare(
        `SELECT ${TIMELINE_COLUMNS}
         FROM audit_events
         WHERE (id = ? OR root_session_id = ?) AND event_type IN (${TIMELINE_EVENT_TYPES})
         ORDER BY started_at ASC, id ASC`,
      ),
      [sessionId, sessionId],
    );

    const events = timelineRows.map(buildAuditEvent).filter((e): e is AuditEvent => e !== null);

    // Every kind-scoped read of ONE session below is pinned to a root-led
    // index. The store never runs ANALYZE, so the planner prices the
    // alternatives from the schema alone, and from the schema alone it takes an
    // event-type-led index for `event_type = '…'` — every row of that kind in
    // the store, filtered to the session afterwards — over the session's own
    // children: the token sum, the tool grouping and the model list each read
    // ~7 ms of a never-analyzed 20k-capture store for a 500-capture session,
    // growing with the store, against a fraction of a millisecond through the
    // pin. `idx_audit_session_type` for the llm_call reads (partial on the
    // kind, ordered by started_at, which also serves the primary model's
    // ORDER BY), `idx_audit_session` for the rest.
    const tokenRow = getRow<{
      input: number;
      output: number;
      cache_creation: number;
      cache_read: number;
    }>(
      this.db.prepare(
        `SELECT
           coalesce(sum(input_tokens), 0) AS input,
           coalesce(sum(output_tokens), 0) AS output,
           coalesce(sum(cache_creation_input_tokens), 0) AS cache_creation,
           coalesce(sum(cache_read_input_tokens), 0) AS cache_read
         FROM audit_events INDEXED BY idx_audit_session_type
         WHERE root_session_id = ? AND event_type = 'llm_call'`,
      ),
      [sessionId],
    ) ?? { input: 0, output: 0, cache_creation: 0, cache_read: 0 };

    const primaryModel = getRow<{ model: string | null; provider: string | null }>(
      this.db.prepare(
        `SELECT model, provider FROM audit_events INDEXED BY idx_audit_session_type
         WHERE root_session_id = ? AND event_type = 'llm_call'
         ORDER BY started_at ASC, id ASC
         LIMIT 1`,
      ),
      [sessionId],
    );

    // Tool grouping keys off the canonical `tool_name` (what the reconciler
    // writes) and falls back to the fixtures' legacy `tool` key — the read side
    // reading only `$.tool` was why real reconciled sessions showed "0 tool calls".
    const toolRows = allRows<{ tool: string | null; n: number }>(
      this.db.prepare(
        `SELECT coalesce(json_extract(attributes, '$.tool_name'), json_extract(attributes, '$.tool')) AS tool,
                count(*) AS n
         FROM audit_events INDEXED BY idx_audit_session
         WHERE root_session_id = ? AND event_type = 'tool_call'
         GROUP BY coalesce(json_extract(attributes, '$.tool_name'), json_extract(attributes, '$.tool'))`,
      ),
      [sessionId],
    );

    // Models used — the DISTINCT models across this session's `llm_call` leaves
    // (a run can switch models / spawn subagents). Derived here rather than read
    // off the root's `$.models` attribute: the live capture path stores no
    // `models` on the root, and this recovers the list for pre-enrichment rows.
    // Falls back to the root attribute when no leaves exist (fixture rows).
    const modelRows = allRows<{ model: string }>(
      this.db.prepare(
        `SELECT DISTINCT model FROM audit_events INDEXED BY idx_audit_session_type
         WHERE root_session_id = ? AND event_type = 'llm_call' AND model IS NOT NULL AND model <> ''
         ORDER BY model`,
      ),
      [sessionId],
    );
    const derivedModels = modelRows.map((r) => r.model);

    const commits = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events INDEXED BY idx_audit_session
           WHERE root_session_id = ? AND event_type = 'commit'`,
      [sessionId],
    );

    // `rollupsFor` already computes this session's last descendant activity
    // (folding each event's ended_at); toSummary maxes it with the root's own
    // started_at, so the detail pane's status/duration match the list exactly.
    const rollup = this.rollupsFor([sessionId]).get(sessionId) ?? {
      turns: 0,
      findings: 0,
      shares: 0,
      lastActivityMs: 0,
    };

    const tokens: TokenRollup = {
      sessionId,
      model: primaryModel?.model ?? '',
      provider: primaryModel?.provider ?? '',
      inputTokens: tokenRow.input,
      outputTokens: tokenRow.output,
      cacheCreation: tokenRow.cache_creation,
      cacheRead: tokenRow.cache_read,
      totalTokens: tokenRow.input + tokenRow.output + tokenRow.cache_creation + tokenRow.cache_read,
      estimatedCostUsd: null,
    };

    const session: ActivitySession = {
      ...toSummary(rootRow, rollup, this.now()),
      host: rootRow.host ?? '',
      cwd: rootRow.cwd ?? '',
      models: derivedModels.length > 0 ? derivedModels : safeParseStringArray(rootRow.models),
      version: rootRow.version ?? '',
      tokens,
      tools: Object.fromEntries(toolRows.flatMap((r) => (r.tool ? [[r.tool, r.n] as const] : []))),
      files: safeParseStringArray(rootRow.files),
      commits,
      events,
    };

    return Promise.resolve(session);
  }

  /**
   * Cross-session token report — every `llm_call` in the store (or in a
   * `started_at >= fromMs` window, the Activity page's range) grouped per
   * session, with USD cost DERIVED at read time via the shared
   * `defaultCostModel` (never stored). The caller collapses these onto
   * per-model rows with `aggregateTokenUsage`.
   *
   * Grouped in SQL over `idx_audit_llm_usage` — one entry per call carrying
   * the members the rollup sums — and priced once per group, which is exact
   * (see LlmUsageRow). Reading the bags and folding them in JS measured 31 ms
   * for a seven-day window at 50k calls, and naming the VIRTUAL columns
   * against the table 40 ms, since each is a json_extract recomputed per row;
   * the index stores the values once, at write, and answers the same window in
   * 8.5 ms. `INDEXED BY` is deliberate: with or without ANALYZE statistics the
   * planner prefers the general event-type index and fetches every row to
   * recompute the columns it could have read. The index is one every open
   * store carries, since opening runs the migrations, so the hard requirement
   * `INDEXED BY` introduces is already met; token-rollup-plans.test.ts pins
   * the plan. All-time is a scan of the whole index — still one narrow entry
   * per call, no bag parsed.
   */
  tokenReports(fromMs?: number): Promise<SessionTokenReport[]> {
    const rows = allRows<LlmUsageRow>(
      this.db.prepare(
        `${LLM_USAGE_SELECT}
           FROM audit_events INDEXED BY idx_audit_llm_usage
          WHERE ${LLM_USAGE_SCOPE}${fromMs === undefined ? '' : ' AND started_at >= ?'}
          ${LLM_USAGE_GROUP}`,
      ),
      fromMs === undefined ? undefined : [fromMs],
    );
    return Promise.resolve(buildTokenReports(usageLeaves(rows), defaultCostModel));
  }

  /**
   * One session's token report — its `llm_call`s grouped per (provider,
   * model, tier) with derived cost, or `null` when the session made no
   * `llm_call`s (an empty/tool-only session). Feeds the session-detail pane's
   * per-model breakdown + estimated cost. The same rollup as `tokenReports`,
   * seeking one root through a root-led `llm_call` index; the bag-reading fold
   * it replaces walked every `llm_call` in the store to find one session's.
   */
  tokenReportForSession(sessionId: string): Promise<SessionTokenReport | null> {
    const rows = allRows<LlmUsageRow>(
      this.db.prepare(
        `${LLM_USAGE_SELECT}
           FROM audit_events
          WHERE ${LLM_USAGE_SCOPE} AND root_session_id = ?
          ${LLM_USAGE_GROUP}`,
      ),
      [sessionId],
    );
    const reports = buildTokenReports(usageLeaves(rows), defaultCostModel);
    // buildTokenReports groups by session, so a single-session read yields at
    // most one report (its rollups are the per-model breakdown).
    return Promise.resolve(reports[0] ?? null);
  }

  /**
   * The DISTINCT harnesses that actually have sessions (optionally within a
   * `started_at >= fromMs` window), so the filter can offer only the harnesses
   * present rather than the full enum. Each stored value is normalized through
   * the SAME `toHarness` default the list uses (missing → DEFAULT_HARNESS), so
   * a store of bare (harness-less) roots surfaces exactly that one harness.
   */
  harnessFacets(fromMs?: number): Promise<HarnessType[]> {
    const where = fromMs === undefined ? '' : ' AND started_at >= ?';
    const stmt = this.db.prepare(
      `SELECT DISTINCT coalesce(json_extract(attributes, '$.harness'), '${DEFAULT_HARNESS}') AS harness
         FROM audit_events WHERE ${SESSION_ROOT}${where}`,
    );
    const rows = allRows<{ harness: string | null }>(
      stmt,
      fromMs === undefined ? undefined : [fromMs],
    );
    const seen = new Set<HarnessType>();
    for (const row of rows) seen.add(toHarness(row.harness));
    return Promise.resolve([...seen]);
  }

  /**
   * Per-session turns/findings/shares + last-activity for a page of session ids,
   * in grouped queries (not one per row). An id with no matching rows still
   * appears in the map with zeros. Returns an empty map for an empty id list (an
   * empty `IN ()` is invalid SQL).
   */
  private rollupsFor(sessionIds: string[]): Map<string, SessionRollup> {
    const result = new Map<string, SessionRollup>(
      sessionIds.map((id) => [id, { turns: 0, findings: 0, shares: 0, lastActivityMs: 0 }]),
    );
    if (sessionIds.length === 0) return result;

    const inClause = placeholders(sessionIds.length);

    // Most recent descendant activity per session — the later of each event's
    // start and end (a long tool call counts from when it ENDED); the caller
    // maxes this with the root's own started_at to decide liveness (see
    // resolveLifecycle). Two index seeks per session — `max(started_at)` is
    // the last entry under the root in idx_audit_session, `max(ended_at)` the
    // last in idx_audit_session_ended — instead of one walk over every
    // descendant of the page's sessions, which cost the page its every row on
    // each load. The ids travel as one JSON array through json_each, so it is
    // one statement whatever the page size.
    const lastActivityRows = allRows<{ id: string; ms: number | null; me: number | null }>(
      this.db.prepare(
        `SELECT ids.value AS id,
                (SELECT max(started_at) FROM audit_events e WHERE e.root_session_id = ids.value) AS ms,
                (SELECT max(ended_at) FROM audit_events e
                  WHERE e.root_session_id = ids.value AND e.ended_at IS NOT NULL) AS me
         FROM json_each(?) AS ids`,
      ),
      [JSON.stringify(sessionIds)],
    );
    for (const row of lastActivityRows) {
      const entry = result.get(row.id);
      const last = Math.max(row.ms ?? 0, row.me ?? 0);
      if (entry && last > 0) entry.lastActivityMs = last;
    }

    // Each kind-scoped rollup below is pinned to its partial index. The store
    // never runs ANALYZE, so the planner prices every alternative from the
    // schema alone — and from the schema alone it takes the event-type index
    // for `event_type = 'prompt'`, which is every prompt in the store and a
    // sort, over the per-root partial built for exactly this read: 0.4 ms →
    // 4.0 ms across a ten-fold store on a never-analyzed corpus, against 0.07
    // ms flat through the pin. Same tool, same reason as liveNow above and
    // tokenReports below; activity-probe-plans.test.ts pins each plan.
    const turnsRows = allRows<{ id: string | null; n: number }>(
      this.db.prepare(
        `SELECT root_session_id AS id, count(*) AS n
         FROM audit_events INDEXED BY idx_audit_session_prompt
         WHERE root_session_id IN (${inClause}) AND event_type = 'prompt'
         GROUP BY root_session_id`,
      ),
      sessionIds,
    );
    for (const row of turnsRows) {
      if (row.id === null) continue;
      const entry = result.get(row.id);
      if (entry) entry.turns = row.n;
    }

    // The live OSS capture path writes no `prompt` audit events, so turns are
    // instead the DISTINCT `run_key` (the parent prompt's id) across the session's
    // `llm_call` leaves — one turn per user prompt. Take the max of the two so
    // fixture rows (which seed `prompt` events) and real reconciled rows (which
    // carry `run_key`) both report correctly, and a session with neither reads 0.
    const runKeyRows = allRows<{ id: string | null; n: number }>(
      this.db.prepare(
        `SELECT root_session_id AS id,
                count(DISTINCT json_extract(attributes, '$.run_key')) AS n
         FROM audit_events INDEXED BY idx_audit_session_run_key
         WHERE root_session_id IN (${inClause}) AND event_type = 'llm_call'
           AND json_extract(attributes, '$.run_key') IS NOT NULL
         GROUP BY root_session_id`,
      ),
      sessionIds,
    );
    for (const row of runKeyRows) {
      if (row.id === null) continue;
      const entry = result.get(row.id);
      if (entry) entry.turns = Math.max(entry.turns, row.n);
    }

    // inspection_findings only — same deliberate two-store split as
    // todayStats.findingsToday (see the comment there): live-capture findings
    // (findings ⋈ events) are excluded to avoid double-counting a value both
    // enforced live and re-detected in the session's persisted transcript.
    const findingsRows = allRows<{ id: string | null; n: number }>(
      this.db.prepare(
        `SELECT e.root_session_id AS id, count(*) AS n FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         WHERE e.root_session_id IN (${inClause})
         GROUP BY e.root_session_id`,
      ),
      sessionIds,
    );
    for (const row of findingsRows) {
      if (row.id === null) continue;
      const entry = result.get(row.id);
      if (entry) entry.findings = row.n;
    }

    const sharesRows = allRows<{ id: string | null; n: number }>(
      this.db.prepare(
        `SELECT root_session_id AS id,
                count(DISTINCT json_extract(attributes, '$.destination')) AS n
         FROM audit_events INDEXED BY idx_audit_session_share
         WHERE root_session_id IN (${inClause}) AND event_type = 'share'
         GROUP BY root_session_id`,
      ),
      sessionIds,
    );
    for (const row of sharesRows) {
      if (row.id === null) continue;
      const entry = result.get(row.id);
      if (entry) entry.shares = row.n;
    }

    return result;
  }
}
