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
  Harness,
  isoToEpochMillis,
  SessionStatus,
} from '@akasecurity/schema';

import { parseJsonObject, safeJson } from '../internal/json.ts';
import { allRows, countScalar, getRow, intToBool, mapRowsTolerant } from '../internal/rows.ts';
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

// A single event's "activity instant": the later of when it started and when it
// ended (a null `ended_at` — the common case — falls back to the start). Folding
// `ended_at` in means one long-running descendant (a subagent, a build, a 35-min
// tool call) keeps a session live off its END, not its start, so it can't flip to
// `completed` mid-work. Bare column names deliberately resolve to the innermost
// query's `audit_events` alias in every call site.
const LAST_ACTIVITY_EXPR = `max(started_at, coalesce(ended_at, started_at))`;

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

interface SessionCursor {
  startedAtMs: number;
  id: string;
}

// Opaque base64url keyset cursor of the last item's {startedAtMs, id}, most-
// recent-first (same convention as services/activity.ts). A stale/undecodable
// cursor restarts from the top rather than throwing.
function encodeCursor(payload: SessionCursor): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function decodeCursor(cursor: string): SessionCursor | null {
  const parsed = parseJsonObject(Buffer.from(cursor, 'base64url').toString('utf8'));
  if (
    parsed !== undefined &&
    'startedAtMs' in parsed &&
    'id' in parsed &&
    typeof parsed.startedAtMs === 'number' &&
    typeof parsed.id === 'string'
  ) {
    return parsed as unknown as SessionCursor;
  }
  return null;
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

/** Parse a JSON-array attribute (branches/models/files), degrading to [] on a
 * missing or malformed value — never throws on a legacy-shaped row. */
function safeParseStringArray(raw: string | null): string[] {
  if (!raw) return [];
  const parsed = safeJson<unknown>(raw, null);
  return Array.isArray(parsed) ? (parsed as string[]) : [];
}

/** Validate a raw harness attribute against the enum, defaulting to `claudecode`
 * so the FE's `PROVIDERS[harness]` lookup can never miss (crash the view). */
function toHarness(raw: string | null): HarnessType {
  const parsed = Harness.safeParse(raw);
  return parsed.success ? parsed.data : 'claudecode';
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

// A session root row. EVERY `event_type='session'` row counts, and a row missing
// the fixture/live attributes degrades to defensive defaults (see
// `toHarness`/`toSummary`) rather than being hidden — so dashboards render
// identically for bare session rows too, not just for fully-attributed seed data.
const SESSION_ROOT = `event_type = 'session'`;

/**
 * Activity read views over the tenant-free local `audit_events` store. Runs the
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

    const sessionsToday = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events
           WHERE ${SESSION_ROOT} AND started_at >= ? AND started_at < ?`,
      [startMs, endMs],
    );

    // liveNow — open sessions still recently active (tz-independent, no day
    // boundary). "Open" alone is not enough: the local store never stamps
    // `ended_at` on the root, so a bare `ended_at IS NULL` count would return the
    // entire session history. A session is live only while its most recent
    // activity is inside LIVE_ACTIVITY_WINDOW_MS. "Most recent activity" folds in
    // each descendant's OWN `ended_at` (via `LAST_ACTIVITY_EXPR`) so a single
    // long-running event — a subagent, a build, a 35-min tool call — keeps the
    // session live off its end time, not its start.
    const liveThreshold = this.now() - LIVE_ACTIVITY_WINDOW_MS;
    const liveNow = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events s
           WHERE s.event_type = 'session' AND s.ended_at IS NULL
             AND max(
               s.started_at,
               coalesce(
                 (SELECT max(${LAST_ACTIVITY_EXPR}) FROM audit_events e WHERE e.root_session_id = s.id),
                 s.started_at
               )
             ) >= ?`,
      [liveThreshold],
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
    const cursor = query.cursor ? decodeCursor(query.cursor) : null;
    const toMs = query.to ? isoToEpochMillis(query.to) : this.now();
    const fromMs = query.from ? isoToEpochMillis(query.from) : undefined;

    const conditions: string[] = [SESSION_ROOT];
    const params: unknown[] = [];

    if (query.harness && query.harness.length > 0) {
      // Coalesce the stored harness to the SAME default the read side applies
      // (`toHarness`: missing → 'claudecode'). The live capture path historically
      // wrote no `harness` attribute, so a bare `$.harness IN (...)` matched zero
      // rows — filtering by "claudecode" returned nothing even though every bare
      // row RENDERS as claudecode. Coalescing makes the filter agree with the view.
      conditions.push(
        `coalesce(json_extract(attributes, '$.harness'), 'claudecode') IN (${placeholders(query.harness.length)})`,
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
      hasMore && last ? encodeCursor({ startedAtMs: last.started_at, id: last.id }) : null;

    return Promise.resolve({ items, nextCursor });
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
         WHERE id = ? OR root_session_id = ?
         ORDER BY started_at ASC, id ASC`,
      ),
      [sessionId, sessionId],
    );

    const events = timelineRows.map(buildAuditEvent).filter((e): e is AuditEvent => e !== null);

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
         FROM audit_events
         WHERE root_session_id = ? AND event_type = 'llm_call'`,
      ),
      [sessionId],
    ) ?? { input: 0, output: 0, cache_creation: 0, cache_read: 0 };

    const primaryModel = getRow<{ model: string | null; provider: string | null }>(
      this.db.prepare(
        `SELECT model, provider FROM audit_events
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
         FROM audit_events
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
        `SELECT DISTINCT model FROM audit_events
         WHERE root_session_id = ? AND event_type = 'llm_call' AND model IS NOT NULL AND model <> ''
         ORDER BY model`,
      ),
      [sessionId],
    );
    const derivedModels = modelRows.map((r) => r.model);

    const commits = countScalar(
      this.db,
      `SELECT count(*) AS n FROM audit_events
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
   * Cross-session token report — every `llm_call` leaf (optionally windowed to
   * `started_at >= fromMs`) grouped into per-session `SessionTokenReport`s, with
   * USD cost DERIVED at read time via the shared `defaultCostModel` (never
   * stored). `fromMs` lets the Activity page scope the usage panel to its
   * selected time range; omit it for all-time (the CLI/TUI overview). The
   * caller collapses these onto per-model rows with `aggregateTokenUsage`.
   */
  tokenReports(fromMs?: number): Promise<SessionTokenReport[]> {
    // Omit `fromMs` entirely when unset (exactOptionalPropertyTypes rejects an
    // explicit `undefined`) so the helper reads all-time.
    const leaves = this.readLlmCallLeaves(fromMs === undefined ? {} : { fromMs });
    return Promise.resolve(buildTokenReports(leaves, defaultCostModel));
  }

  /**
   * One session's token report — its `llm_call` leaves grouped per (provider,
   * model) with derived cost, or `null` when the session made no `llm_call`s
   * (an empty/tool-only session). Feeds the session-detail pane's per-model
   * breakdown + estimated cost.
   */
  tokenReportForSession(sessionId: string): Promise<SessionTokenReport | null> {
    const reports = buildTokenReports(this.readLlmCallLeaves({ sessionId }), defaultCostModel);
    // buildTokenReports groups by session, so a single-session read yields at
    // most one report (its rollups are the per-model breakdown).
    return Promise.resolve(reports[0] ?? null);
  }

  /**
   * The DISTINCT harnesses that actually have sessions (optionally within a
   * `started_at >= fromMs` window), so the filter can offer only the harnesses
   * present rather than the full enum. Each stored value is normalized through
   * the SAME `toHarness` default the list uses (missing → 'claudecode'), so a
   * store of bare (harness-less) roots surfaces exactly `['claudecode']`.
   */
  harnessFacets(fromMs?: number): Promise<HarnessType[]> {
    const where = fromMs === undefined ? '' : ' AND started_at >= ?';
    const stmt = this.db.prepare(
      `SELECT DISTINCT coalesce(json_extract(attributes, '$.harness'), 'claudecode') AS harness
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
   * The raw `llm_call` leaves (session id + parsed attribute bag) for the token
   * rollups, optionally narrowed to one session and/or a `started_at >= fromMs`
   * window. A leaf whose attributes blob is NULL or unparseable is skipped
   * (best-effort read — a corrupt bag never breaks the report). `root_session_id`
   * is the leaf's session (the reconciler sets parent_id = root_session_id).
   */
  private readLlmCallLeaves(opts: { sessionId?: string; fromMs?: number } = {}): LlmCallLeaf[] {
    const conditions = ["event_type = 'llm_call'", 'attributes IS NOT NULL'];
    const params: unknown[] = [];
    if (opts.sessionId !== undefined) {
      conditions.push('root_session_id = ?');
      params.push(opts.sessionId);
    }
    if (opts.fromMs !== undefined) {
      conditions.push('started_at >= ?');
      params.push(opts.fromMs);
    }
    const rows = allRows<{ sessionId: string | null; attributes: string }>(
      this.db.prepare(
        `SELECT root_session_id AS sessionId, attributes
           FROM audit_events
          WHERE ${conditions.join(' AND ')}`,
      ),
      params as SQLInputValue[],
    );

    // A leaf with no root session can't be attributed and is dropped; a leaf
    // whose attributes blob is unparseable is skipped (best-effort read).
    return mapRowsTolerant(
      rows.filter(
        (row): row is { sessionId: string; attributes: string } => row.sessionId !== null,
      ),
      (row) => ({
        sessionId: row.sessionId,
        attributes: JSON.parse(row.attributes) as LlmCallAttributes,
      }),
    );
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

    // Most recent descendant activity per session (each event's later of
    // start/end — see LAST_ACTIVITY_EXPR); the caller maxes this with the root's
    // own started_at to decide liveness (see resolveLifecycle).
    const lastActivityRows = allRows<{ id: string | null; m: number | null }>(
      this.db.prepare(
        `SELECT root_session_id AS id, max(${LAST_ACTIVITY_EXPR}) AS m FROM audit_events
         WHERE root_session_id IN (${inClause})
         GROUP BY root_session_id`,
      ),
      sessionIds,
    );
    for (const row of lastActivityRows) {
      if (row.id === null) continue;
      const entry = result.get(row.id);
      if (entry && row.m !== null) entry.lastActivityMs = row.m;
    }

    const turnsRows = allRows<{ id: string | null; n: number }>(
      this.db.prepare(
        `SELECT root_session_id AS id, count(*) AS n FROM audit_events
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
         FROM audit_events
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
         FROM audit_events
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
