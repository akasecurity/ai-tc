/**
 * The token rollups must be answered from the usage index, and must name the
 * usage columns rather than ship the bags — pinned as `EXPLAIN QUERY PLAN`
 * fragments and as the statement text, read by read.
 *
 * `hot-read-query-plans.test.ts` cannot say either. The old read was a SEARCH
 * there too: it selected every `llm_call` bag in the window, parsed each in JS
 * and folded — 31 ms at 50k rows for a seven-day window — and the per-session
 * form of it walked EVERY `llm_call` in the store through the event-type index
 * to find one session's (17 ms at 50k, growing with the store). Grouping in
 * SQL over `idx_audit_llm_usage` — one covering entry per call carrying the
 * members the rollup sums — answers the window from the index alone (8.8 ms
 * at 50k) and the session from `idx_audit_session_type` (0.2 ms). What each
 * read must be seen doing is stated here, so a rewrite that quietly returns
 * to the bags fails.
 *
 * The windowed and all-time reads are pinned to the usage index by name: the
 * repository carries `INDEXED BY` on them because, with or without `ANALYZE`
 * statistics, the planner otherwise prefers the general event-type index and
 * fetches every row to recompute the VIRTUAL columns it could have read.
 *
 * The plan never says COVERING here, and cannot: SQLite counts a VIRTUAL
 * generated column's dependency on `attributes` as a reference to the row, so
 * an index over such columns is never labelled covering even though the values
 * are read from it. That the values ARE read from it is what the timing shows
 * — the same 8.5 ms with `event_type` added to the index and the bag predicate
 * dropped, against 40 ms through the event-type index — so this file pins the
 * index by name and the bench carries the number.
 */
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteActivityRepository } from '../../src/repositories/activity.ts';
import { corpusConnection } from '../helpers/corpus.ts';
import type { RecordedQuery } from '../helpers/query-plans.ts';
import { recordingConnection } from '../helpers/query-plans.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const DAY_MS = 86_400_000;
const NOW = Date.parse('2026-09-01T00:00:00Z');
const SESSIONS = 20;
const CALLS = 400;

/** The columns the rollup must read, so a statement that ships the bag instead fails. */
const USAGE_COLUMNS = [
  'provider',
  'model',
  'service_tier',
  'input_tokens',
  'output_tokens',
  'cache_creation_input_tokens',
  'cache_read_input_tokens',
  'ephemeral_1h_input_tokens',
  'ephemeral_5m_input_tokens',
  'web_search_requests',
] as const;

interface Read {
  readonly name: string;
  readonly run: (activity: SqliteActivityRepository) => unknown;
  readonly mustUse: readonly RegExp[];
  readonly mustNotUse: readonly RegExp[];
}

const READS: readonly Read[] = [
  {
    name: 'tokenReports over a window',
    run: (a) => a.tokenReports(NOW - 7 * DAY_MS),
    mustUse: [/SEARCH audit_events USING (COVERING )?INDEX idx_audit_llm_usage \(started_at>\?\)/],
    mustNotUse: [/idx_audit_type_t/, /idx_audit_events_sync/],
  },
  {
    name: 'tokenReports all-time',
    run: (a) => a.tokenReports(),
    mustUse: [/SCAN audit_events USING (COVERING )?INDEX idx_audit_llm_usage/],
    mustNotUse: [/idx_audit_type_t/, /idx_audit_events_sync/],
  },
  {
    name: 'tokenReportForSession',
    run: (a) => a.tokenReportForSession('sess-3'),
    mustUse: [/SEARCH audit_events USING INDEX idx_audit_session_type \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_type_t/, /idx_audit_events_sync/],
  },
];

function seed(raw: DatabaseSync): void {
  const insert = raw.prepare(
    `INSERT INTO audit_events (id, event_type, started_at, root_session_id, parent_id, attributes)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  raw.exec('BEGIN');
  for (let s = 0; s < SESSIONS; s += 1) {
    insert.run(`sess-${String(s)}`, 'session', NOW - (SESSIONS - s) * DAY_MS, null, null, '{}');
  }
  for (let i = 0; i < CALLS; i += 1) {
    const s = i % SESSIONS;
    insert.run(
      `llm-${String(i)}`,
      'llm_call',
      NOW - (SESSIONS - s) * DAY_MS + i * 1000,
      `sess-${String(s)}`,
      `sess-${String(s)}`,
      JSON.stringify({
        model: i % 2 === 0 ? 'claude-opus-5' : 'claude-sonnet-5',
        provider: 'anthropic',
        input_tokens: 100 + i,
        output_tokens: 10 + i,
        cache_creation_input_tokens: i % 50,
        cache_read_input_tokens: i % 500,
        ephemeral_5m_input_tokens: i % 50,
        service_tier: i % 10 === 0 ? 'batch' : 'standard',
        web_search_requests: i % 20 === 0 ? 1 : 0,
      }),
    );
  }
  raw.exec('COMMIT');
}

function planOf(db: DatabaseSync, q: RecordedQuery): string {
  return (
    db.prepare(`EXPLAIN QUERY PLAN ${q.sql}`).all(...(q.args as SQLInputValue[])) as {
      detail: string;
    }[]
  )
    .map((row) => row.detail)
    .join('\n');
}

describe('the token rollups are answered from the usage index', () => {
  let store: OwnedTempStore;
  let raw: DatabaseSync;
  const statements = new Map<string, RecordedQuery[]>();

  beforeAll(() => {
    store = createTempStore('aka-token-rollup-plans-', { migrated: true });
    raw = corpusConnection(store.open());
    seed(raw);
    const recorded: RecordedQuery[] = [];
    const activity = new SqliteActivityRepository(recordingConnection(raw, recorded), () => NOW);
    for (const read of READS) {
      recorded.length = 0;
      void read.run(activity);
      statements.set(read.name, [...recorded]);
    }
  });

  afterAll(() => {
    store.destroy();
  });

  for (const read of READS) {
    it(`${read.name} is one statement that names the usage columns`, () => {
      const issued = statements.get(read.name) ?? [];
      expect(issued, `${read.name} issued ${String(issued.length)} statements`).toHaveLength(1);
      const [q] = issued;
      if (!q) throw new Error('unreachable: length asserted above');
      for (const column of USAGE_COLUMNS) {
        expect(q.sql, `${read.name} does not read ${column}`).toContain(column);
      }
      // Shipping the bag is the fold this replaced: a statement that selects
      // it has gone back to parsing every call in JS.
      expect(q.sql, `${read.name} ships the attribute bag`).not.toMatch(
        /SELECT[^]*\battributes\b[^]*FROM/,
      );
    });

    it(`${read.name} is served by its index`, () => {
      const [q] = statements.get(read.name) ?? [];
      if (!q) throw new Error(`${read.name} issued no statement`);
      const plan = planOf(raw, q);
      for (const fragment of read.mustUse) {
        expect(plan, `${read.name} plan lacks ${String(fragment)}:\n${plan}`).toMatch(fragment);
      }
      for (const fragment of read.mustNotUse) {
        expect(plan, `${read.name} plan still uses ${String(fragment)}:\n${plan}`).not.toMatch(
          fragment,
        );
      }
    });
  }
});
