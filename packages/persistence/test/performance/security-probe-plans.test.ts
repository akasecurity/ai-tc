/**
 * The /security page's four broad rollups must be answered from
 * `idx_audit_capture_rollup`, and must not fall back to an event-type-led
 * index that fetches the row.
 *
 * `hot-read-query-plans.test.ts` cannot say this. Every one of these reads was
 * a SEARCH there before and is a SEARCH now, and its classifier treats
 * `USING INDEX x` and `USING COVERING INDEX x` alike — so the distinction that
 * actually costs is invisible to it. What costs is the ROW FETCH: `content` is
 * declared before `attributes` in the record and holds whole file bodies on a
 * `code_change`, so on a real store most rows spill to overflow pages and
 * reaching either `id` or a VIRTUAL column over the bag walks that chain past
 * the body. Measured on a 6 GB store: the same 53,383 rows cost 14 ms read
 * through a covering index over two VIRTUAL columns and 5,020 ms read from the
 * rows — and `topSources`, which needs `repo` for every capture event in its
 * window, cost 8,278 ms of the page's ~15 s.
 *
 * The reads carry `INDEXED BY` because the planner prices from the schema —
 * nothing here runs `ANALYZE` — and otherwise prefers the general event-type
 * index. `topSources`'s plan will NOT say COVERING and cannot: SQLite counts a
 * VIRTUAL generated column's dependency on `attributes` as a reference to the
 * row even while it reads the value from the index. So the index is pinned by
 * NAME and the fallbacks are refused by name; the label is not the evidence.
 */
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteSecurityRepository } from '../../src/repositories/security.ts';
import { corpusConnection } from '../helpers/corpus.ts';
import type { RecordedQuery } from '../helpers/query-plans.ts';
import { recordingConnection } from '../helpers/query-plans.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const DAY_MS = 86_400_000;
const NOW = Date.parse('2026-09-01T00:00:00Z');
const EVENTS = 300;
const CAPTURE_KINDS = ['prompt', 'response', 'code_change', 'tool_use'] as const;

interface Read {
  readonly name: string;
  readonly run: (security: SqliteSecurityRepository) => unknown;
  readonly mustUse: readonly RegExp[];
  readonly mustNotUse: readonly RegExp[];
}

/**
 * Every one of these joins audit_events, so every one must ride the rollup index.
 * COVERING is the form to require wherever it is reachable, because it is the
 * only thing in the plan text that says the row is never fetched — a read that
 * grows a reference to a column outside the index keeps the index and silently
 * goes back to walking the overflow chain, and the un-suffixed form cannot tell
 * the two apart.
 */
const COVERED_BY_ROLLUP = /SEARCH e USING COVERING INDEX idx_audit_capture_rollup/;
/**
 * `topSources` is the one read that cannot reach the COVERING label: it names
 * `repo`, and SQLite counts a VIRTUAL generated column's dependency on
 * `attributes` as a reference to the row even while it reads the value from the
 * index. The value IS read from the index — measured on a 6 GB store, two such
 * columns over 53,383 rows cost 14 ms through a covering index against 5,020 ms
 * from the rows — so this one is pinned by name and the timing is the evidence.
 */
const SERVED_BY_ROLLUP = /SEARCH e USING (COVERING )?INDEX idx_audit_capture_rollup/;
/** What the planner takes when the rollup index is missing or unnamed — each fetches the row. */
const FALLBACKS = [/idx_audit_type_t/, /idx_audit_events_sync/, /idx_audit_started_at/] as const;

const READS: readonly Read[] = [
  {
    name: 'severitySummary',
    run: (s) => s.severitySummary(),
    mustUse: [COVERED_BY_ROLLUP],
    mustNotUse: FALLBACKS,
  },
  {
    name: 'topSources',
    run: (s) => s.topSources('30d', { limit: 5 }),
    mustUse: [SERVED_BY_ROLLUP],
    mustNotUse: FALLBACKS,
  },
  {
    name: 'recommendationInputs',
    run: (s) => s.recommendationInputs(),
    mustUse: [COVERED_BY_ROLLUP],
    mustNotUse: FALLBACKS,
  },
  {
    name: 'findingsTimeseries',
    run: (s) => s.findingsTimeseries('30d'),
    mustUse: [COVERED_BY_ROLLUP],
    mustNotUse: FALLBACKS,
  },
  {
    name: 'enforcementActions',
    run: (s) => s.enforcementActions('30d'),
    mustUse: [COVERED_BY_ROLLUP],
    mustNotUse: FALLBACKS,
  },
];

function seed(raw: DatabaseSync): void {
  const event = raw.prepare(
    `INSERT INTO audit_events (id, event_type, started_at, content, attributes) VALUES (?, ?, ?, ?, ?)`,
  );
  const def = raw.prepare(
    `INSERT INTO inspection_definitions (id, rule_id, name, category, severity, definition, version)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  const finding = raw.prepare(
    `INSERT INTO inspection_findings
       (id, audit_event_id, inspection_definition_id, span_start, span_end, masked_match, action_taken, confidence, finding_key)
     VALUES (?, ?, ?, 0, 8, 'A******E', ?, 1.0, ?)`,
  );
  raw.exec('BEGIN');
  for (const [i, severity] of ['critical', 'high', 'medium', 'low'].entries()) {
    def.run(`def-${severity}`, `rule.${severity}`, severity, 'secret', severity, '{}', '1');
    void i;
  }
  for (let i = 0; i < EVENTS; i += 1) {
    const kind = CAPTURE_KINDS[i % CAPTURE_KINDS.length] ?? 'prompt';
    event.run(
      `evt-${String(i)}`,
      kind,
      // Inside the 30d window the page's reads ask for.
      NOW - (i % 25) * DAY_MS - 1000,
      'body',
      JSON.stringify({ repo: `repo-${String(i % 3)}`, file_path: `src/f${String(i)}.ts` }),
    );
    const severity = ['critical', 'high', 'medium', 'low'][i % 4] ?? 'low';
    finding.run(
      `find-${String(i)}`,
      `evt-${String(i)}`,
      `def-${severity}`,
      i % 5 === 0 ? 'block' : 'warn',
      `key-${String(i)}`,
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

describe('the /security rollups are answered from the capture-rollup index', () => {
  let store: OwnedTempStore;
  let raw: DatabaseSync;
  const statements = new Map<string, RecordedQuery[]>();

  beforeAll(() => {
    store = createTempStore('aka-security-probe-plans-', { migrated: true });
    raw = corpusConnection(store.open());
    seed(raw);
    const recorded: RecordedQuery[] = [];
    const security = new SqliteSecurityRepository(recordingConnection(raw, recorded), () => NOW);
    for (const read of READS) {
      recorded.length = 0;
      void read.run(security);
      statements.set(read.name, [...recorded]);
    }
  });

  afterAll(() => {
    store.destroy();
  });

  for (const read of READS) {
    it(`${read.name} rides idx_audit_capture_rollup`, () => {
      const issued = statements.get(read.name) ?? [];
      // A read that issued nothing would satisfy every mustNotUse below for free.
      expect(issued.length, `${read.name} issued no statement`).toBeGreaterThan(0);
      const joining = issued.filter((q) => q.sql.includes('JOIN audit_events'));
      expect(joining.length, `${read.name} issued no audit_events join`).toBeGreaterThan(0);
      for (const q of joining) {
        // The hint itself, pinned as TEXT. The planner happens to reach for
        // this index unaided today, so the plan assertions below stay green
        // without it — which makes them silent about a removal. The hint is
        // what keeps the choice from depending on that, since an index added
        // later can tempt the planner elsewhere on a store with no ANALYZE
        // statistics.
        expect(q.sql, `${read.name} dropped its INDEXED BY hint`).toContain(
          'INDEXED BY idx_audit_capture_rollup',
        );
        const plan = planOf(raw, q);
        for (const fragment of read.mustUse) {
          expect(plan, `${read.name} plan lacks ${String(fragment)}:\n${plan}`).toMatch(fragment);
        }
        for (const fragment of read.mustNotUse) {
          expect(plan, `${read.name} plan uses fallback ${String(fragment)}:\n${plan}`).not.toMatch(
            fragment,
          );
        }
      }
    });
  }

  // The positive control: without it every assertion above would pass on a
  // corpus the reads matched nothing in, since an empty plan trips no fallback.
  it('the corpus actually produces findings for these reads to roll up', async () => {
    const security = new SqliteSecurityRepository(raw, () => NOW);
    const severity = await security.severitySummary();
    expect(severity.total).toBeGreaterThan(0);
    const sources = await security.topSources('30d', { limit: 5 });
    expect(sources.items.length).toBeGreaterThan(0);
  });
});
