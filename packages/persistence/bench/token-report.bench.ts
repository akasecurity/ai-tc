/**
 * The token rollup at a realistic local-store size: the repository's read —
 * every `llm_call` in the window grouped in SQL over the usage index migration
 * 0027 adds, one synthetic leaf per group priced once — against the three
 * shapes it replaced or declined: read every bag and fold it in JS (the read as
 * it was), a GROUP BY that names the VIRTUAL columns through the general
 * event-type index (each column a json_extract recomputed per row), and a
 * GROUP BY over one multi-path json_extract per row.
 *
 * A real single-machine store observed 2026-09-03 held 55k llm_call rows for
 * three months of one user, with ~460-character bags of fifteen keys; the
 * corpus here is that shape. Run:
 *
 *   pnpm --filter @akasecurity/persistence bench -- bench/token-report.bench.ts
 *
 * MEASURED (arm64 macOS, Node 26, node:sqlite, 50k rows / 500 sessions, min of
 * the run): see the PR that added 0027 for the table; the point is that a
 * VIRTUAL column is only faster than the bag when an index stores its value.
 * Naming the columns against the table recomputes every one per row and loses
 * to V8 parsing the bag (137 ms against 98 ms); reading them out of the usage
 * index, where they were computed once at write, wins by the parse it skips
 * (38 ms all-time, 8.5 ms for a seven-day window against 31 ms).
 *
 * NO ASSERTIONS: a measurement, not a gate. `token-rollup-plans.test.ts` is
 * what pins the read to the index.
 */
import type { DatabaseSync } from 'node:sqlite';

import type { LlmCallAttributes, LlmCallLeaf } from '@akasecurity/schema';
import { buildTokenReports, defaultCostModel } from '@akasecurity/schema';
import { bench, describe } from 'vitest';

import { SqliteActivityRepository } from '../src/repositories/activity.ts';
import { corpusConnection } from '../test/helpers/corpus.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

const SESSIONS = 500;
const LLM_CALLS = 50_000;
const MODELS = ['claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4-5-20251001'];
const NOW = Date.parse('2026-09-01T00:00:00Z');

function seed(raw: DatabaseSync): void {
  const insert = raw.prepare(
    `INSERT INTO audit_events (id, event_type, started_at, root_session_id, parent_id, attributes)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  raw.exec('BEGIN');
  for (let s = 0; s < SESSIONS; s += 1) {
    insert.run(`sess-${String(s)}`, 'session', NOW - (SESSIONS - s) * 3_600_000, null, null, '{}');
  }
  for (let i = 0; i < LLM_CALLS; i += 1) {
    const s = i % SESSIONS;
    insert.run(
      `llm-${String(i)}`,
      'llm_call',
      NOW - (SESSIONS - s) * 3_600_000 + (i % 100) * 1000,
      `sess-${String(s)}`,
      `sess-${String(s)}`,
      JSON.stringify({
        model: MODELS[i % 3],
        provider: 'anthropic',
        input_tokens: 400 + (i % 6000),
        output_tokens: 30 + (i % 1500),
        cache_creation_input_tokens: i % 3000,
        cache_read_input_tokens: i % 40000,
        ephemeral_1h_input_tokens: 0,
        ephemeral_5m_input_tokens: i % 3000,
        service_tier: i % 10 === 0 ? 'batch' : 'standard',
        web_search_requests: i % 20 === 0 ? 1 : 0,
        web_fetch_requests: 0,
        message_id: `msg_${String(i).padStart(24, '0')}`,
        uuid: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
        parent_uuid: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
        run_key: `run-${String(s)}-${String(Math.floor(i / 8))}`,
      }),
    );
  }
  raw.exec('COMMIT');
}

interface GroupedRow {
  sessionId: string;
  provider: string | null;
  model: string | null;
  serviceTier: string | null;
  input: number;
  output: number;
  cacheCreation: number;
  cacheRead: number;
  eph1h: number;
  eph5m: number;
  webSearch: number;
}

/** The grouped rows as synthetic leaves — exact by the cost model's linearity. */
function leavesOf(rows: GroupedRow[]): LlmCallLeaf[] {
  return rows.map((r) => ({
    sessionId: r.sessionId,
    attributes: {
      provider: r.provider ?? 'unknown',
      model: r.model ?? 'unknown',
      input_tokens: r.input,
      output_tokens: r.output,
      cache_creation_input_tokens: r.cacheCreation,
      cache_read_input_tokens: r.cacheRead,
      ephemeral_1h_input_tokens: r.eph1h,
      ephemeral_5m_input_tokens: r.eph5m,
      web_search_requests: r.webSearch,
      ...(r.serviceTier === null ? {} : { service_tier: r.serviceTier }),
    },
  }));
}

const READ_BAGS = `
  SELECT root_session_id AS sessionId, attributes
    FROM audit_events
   WHERE event_type = 'llm_call' AND attributes IS NOT NULL AND root_session_id IS NOT NULL`;

// `INDEXED BY idx_audit_type_t`: without it the planner may take the usage
// index this file exists to compare against, and the case would measure the
// read above twice.
const GROUP_BY_COLUMNS = `
  SELECT root_session_id AS sessionId, provider, model, service_tier AS serviceTier,
         coalesce(sum(input_tokens), 0) AS input,
         coalesce(sum(output_tokens), 0) AS output,
         coalesce(sum(cache_creation_input_tokens), 0) AS cacheCreation,
         coalesce(sum(cache_read_input_tokens), 0) AS cacheRead,
         coalesce(sum(ephemeral_1h_input_tokens), 0) AS eph1h,
         coalesce(sum(ephemeral_5m_input_tokens), 0) AS eph5m,
         coalesce(sum(web_search_requests), 0) AS webSearch
    FROM audit_events INDEXED BY idx_audit_type_t
   WHERE event_type = 'llm_call' AND root_session_id IS NOT NULL AND attributes IS NOT NULL
   GROUP BY root_session_id, provider, model, service_tier`;

// One parse per row: json_extract with several paths returns a JSON array of
// the values, which json_each then unrolls — the alternative when a column
// per member would parse the bag once per column.
const GROUP_BY_ONE_PARSE = `
  SELECT sessionId, provider, model, serviceTier,
         coalesce(sum(input), 0) AS input, coalesce(sum(output), 0) AS output,
         coalesce(sum(cacheCreation), 0) AS cacheCreation, coalesce(sum(cacheRead), 0) AS cacheRead,
         coalesce(sum(eph1h), 0) AS eph1h, coalesce(sum(eph5m), 0) AS eph5m,
         coalesce(sum(webSearch), 0) AS webSearch
    FROM (
      SELECT root_session_id AS sessionId,
             json_extract(v, '$[0]') AS provider, json_extract(v, '$[1]') AS model,
             json_extract(v, '$[2]') AS serviceTier,
             json_extract(v, '$[3]') AS input, json_extract(v, '$[4]') AS output,
             json_extract(v, '$[5]') AS cacheCreation, json_extract(v, '$[6]') AS cacheRead,
             json_extract(v, '$[7]') AS eph1h, json_extract(v, '$[8]') AS eph5m,
             json_extract(v, '$[9]') AS webSearch
        FROM (
          SELECT root_session_id,
                 json_extract(attributes, '$.provider', '$.model', '$.service_tier', '$.input_tokens',
                              '$.output_tokens', '$.cache_creation_input_tokens', '$.cache_read_input_tokens',
                              '$.ephemeral_1h_input_tokens', '$.ephemeral_5m_input_tokens',
                              '$.web_search_requests') AS v
            FROM audit_events
           WHERE event_type = 'llm_call' AND root_session_id IS NOT NULL AND json_valid(attributes)
        )
    )
   GROUP BY sessionId, provider, model, serviceTier`;

describe(`token rollup over ${String(LLM_CALLS)} llm_call rows in ${String(SESSIONS)} sessions`, () => {
  let store: OwnedTempStore | undefined;
  let raw: DatabaseSync | undefined;
  let activity: SqliteActivityRepository | undefined;

  // One store for all three cases, seeded on first use: the seed is the
  // expensive part and every case reads the same rows.
  const setup = (): { raw: DatabaseSync; activity: SqliteActivityRepository } => {
    if (raw !== undefined && activity !== undefined) return { raw, activity };
    store = createTempStore('aka-token-bench-', { migrated: true });
    const db = store.open();
    raw = corpusConnection(db);
    seed(raw);
    activity = new SqliteActivityRepository(raw);
    return { raw, activity };
  };

  bench(
    'the read: SQL GROUP BY over the usage index (0027), fold the groups',
    async () => {
      await setup().activity.tokenReports();
    },
    { time: 3000 },
  );

  bench(
    'read every bag, JSON.parse in JS, fold (the read as it was)',
    () => {
      const rows = setup().raw.prepare(READ_BAGS).all() as unknown as {
        sessionId: string;
        attributes: string;
      }[];
      buildTokenReports(
        rows.map((r) => ({
          sessionId: r.sessionId,
          attributes: JSON.parse(r.attributes) as LlmCallAttributes,
        })),
        defaultCostModel,
      );
    },
    { time: 3000 },
  );

  bench(
    'SQL GROUP BY over the VIRTUAL columns through the event-type index, fold the groups',
    () => {
      const rows = setup().raw.prepare(GROUP_BY_COLUMNS).all() as unknown as GroupedRow[];
      buildTokenReports(leavesOf(rows), defaultCostModel);
    },
    { time: 3000 },
  );

  bench(
    'SQL GROUP BY, one json_extract per row, fold the groups',
    () => {
      const rows = setup().raw.prepare(GROUP_BY_ONE_PARSE).all() as unknown as GroupedRow[];
      buildTokenReports(leavesOf(rows), defaultCostModel);
    },
    { time: 3000 },
  );
});
