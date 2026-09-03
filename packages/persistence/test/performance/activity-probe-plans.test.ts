/**
 * The activity page's per-session probes must be served by the indexes built
 * for them — pinned as `EXPLAIN QUERY PLAN` fragments, statement by statement.
 *
 * `hot-read-query-plans.test.ts` cannot say this. A probe that walks every
 * child of a session through the general `(root_session_id, started_at)` index
 * is a SEARCH there, not a scan, and reads as fine while it fetches a row for
 * every child to look at one column — four of the page's five rollups did
 * exactly that per page, and the `liveNow` counter did it for every open root
 * in the store. What each probe has to do instead is stated here as the index
 * it must be seen using, so a rewrite that quietly falls back to the walk
 * fails. (The fifth rollup, findings per session, still walks: it joins
 * `inspection_findings` through the session's rows and no index on the finding
 * side carries the session.)
 *
 *  - `liveNow` is driven from the rows active in the last thirty minutes —
 *    `idx_audit_started_at` for the ones that started then, `idx_audit_ended_at`
 *    for the ones that ended then — never from a per-root walk.
 *  - The page's last-activity rollup is two index seeks per session:
 *    `max(started_at)` off `idx_audit_session` and `max(ended_at)` off
 *    `idx_audit_session_ended`, both covering.
 *  - The prompt, share and run-key rollups read partial indexes over just
 *    their own kind, so a session's prompts cost its prompts, not its rows.
 *  - The detail pane's kind-scoped reads of one session seek the root.
 *
 * The corpus is never analyzed, because the shipped store never is: SQLite
 * plans every read here from the schema alone, and that is the planner these
 * plans have to hold under. With statistics the three rollups took their
 * partial indexes unpinned; without them they took the event-type index —
 * every row of the kind in the store — which is why every kind-scoped read
 * carries `INDEXED BY` and why this file refuses the event-type-led indexes
 * by name.
 */
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteActivityRepository } from '../../src/repositories/activity.ts';
import { seedActivityCorpus } from '../helpers/activity-corpus.ts';
import { corpusConnection } from '../helpers/corpus.ts';
import type { RecordedQuery } from '../helpers/query-plans.ts';
import { recordingConnection } from '../helpers/query-plans.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const DAY_MS = 86_400_000;
const CORPUS_CAPTURES = 2_000;

interface Probe {
  readonly name: string;
  /** Picks the statement out of the read's recorded statements. */
  readonly statement: (sql: string) => boolean;
  /** Plan fragments that must appear, verbatim `EXPLAIN QUERY PLAN` detail text. */
  readonly mustUse: readonly RegExp[];
  /** Plan fragments that must NOT appear — the walk each probe replaced. */
  readonly mustNotUse: readonly RegExp[];
}

const STATS_PROBES: readonly Probe[] = [
  {
    name: 'liveNow',
    statement: (sql) => sql.includes('ended_at IS NULL') && sql.includes('count(*)'),
    // The three arms through their ranges, AND the outer driven from the list
    // they produce — by primary key, one seek per root active in the window —
    // never enumerating every session root in the store to test each against
    // the list. That outer walk is linear in roots, and it hid inside the
    // stats composite because the four day-windowed counters shrink faster
    // than it grows.
    mustUse: [
      /SEARCH s USING INDEX sqlite_autoindex_audit_events_1 \(id=\?\)/,
      /USING INDEX idx_audit_started_at \(started_at>\?\)/,
      /INDEX idx_audit_ended_at \(ended_at>\?\)/,
    ],
    mustNotUse: [
      /CORRELATED SCALAR SUBQUERY/,
      /SEARCH s USING INDEX idx_audit_(type_t|events_sync)/,
    ],
  },
];

const LIST_PROBES: readonly Probe[] = [
  {
    name: 'lastActivity',
    statement: (sql) => sql.includes('max(started_at)') && sql.includes('max(ended_at)'),
    mustUse: [
      /SEARCH e USING COVERING INDEX idx_audit_session \(root_session_id=\?\)/,
      // `ended_at IS NOT NULL` prints as `ended_at>?` — the seek's second column.
      /SEARCH e USING COVERING INDEX idx_audit_session_ended \(root_session_id=\? AND ended_at>\?\)/,
    ],
    // Load-bearing on SQLite's wording: the positive fragment says COVERING,
    // and this negative one is the same index WITHOUT it — the seek that has
    // to fetch a row per child. `USING INDEX` is not a substring of `USING
    // COVERING INDEX`, which is the only reason the pair is not a
    // contradiction; keep both spellings exact.
    mustNotUse: [/USING INDEX idx_audit_session \(root_session_id=\?\)/],
  },
  // The walk each of these falls back to is an event-type-led index (the
  // general one, or the attached-mode sync index that also leads with the
  // kind) — every row of that kind in the whole store, then a sort — so both
  // are refused by name, alongside the general per-root walk.
  {
    name: 'turns',
    statement: (sql) => sql.includes("event_type = 'prompt'") && sql.includes('GROUP BY'),
    mustUse: [/USING COVERING INDEX idx_audit_session_prompt \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/, /idx_audit_session \(/],
  },
  {
    name: 'runKey',
    statement: (sql) => sql.includes("'$.run_key'") && sql.includes('GROUP BY'),
    mustUse: [/USING INDEX idx_audit_session_run_key \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/, /idx_audit_session_type \(/],
  },
  {
    name: 'shares',
    statement: (sql) => sql.includes("event_type = 'share'") && sql.includes('GROUP BY'),
    mustUse: [/USING INDEX idx_audit_session_share \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/, /idx_audit_session \(/],
  },
];

const DETAIL_PROBES: readonly Probe[] = [
  {
    // `(id = ? OR root_session_id = ?) AND event_type IN (…)`: the root by its
    // key and the descendants through the session index, never the event-type
    // index over every row of eleven kinds.
    name: 'timeline',
    statement: (sql) => sql.includes('AS target_id'),
    mustUse: [
      /SEARCH audit_events USING INDEX sqlite_autoindex_audit_events_1 \(id=\?\)/,
      /SEARCH audit_events USING INDEX idx_audit_session \(root_session_id=\?\)/,
    ],
    mustNotUse: [/idx_audit_(type_t|events_sync)/],
  },
  // The kind-scoped reads of ONE session: each is a root-led seek, never a walk
  // of every row of that kind in the store — which is what a never-analyzed
  // store's planner picks for `root_session_id = ? AND event_type = '…'` when
  // nothing pins it (the token sum, the tool grouping and the model list each
  // read the whole store's llm_calls or tool_calls for one session).
  {
    name: 'tokens',
    statement: (sql) => sql.includes('sum(input_tokens)') && sql.includes('root_session_id = ?'),
    mustUse: [/USING (COVERING )?INDEX idx_audit_session_type \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/],
  },
  {
    name: 'primaryModel',
    statement: (sql) => sql.includes('SELECT model, provider') && sql.includes('LIMIT 1'),
    mustUse: [/USING (COVERING )?INDEX idx_audit_session_type \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/],
  },
  {
    name: 'tools',
    statement: (sql) => sql.includes("event_type = 'tool_call'") && sql.includes('GROUP BY'),
    mustUse: [/USING (COVERING )?INDEX idx_audit_session \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/],
  },
  {
    name: 'models',
    statement: (sql) => sql.includes('SELECT DISTINCT model'),
    mustUse: [/USING (COVERING )?INDEX idx_audit_session_type \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/],
  },
  {
    name: 'commits',
    statement: (sql) => sql.includes("event_type = 'commit'"),
    mustUse: [/USING (COVERING )?INDEX idx_audit_session \(root_session_id=\?\)/],
    mustNotUse: [/idx_audit_(type_t|events_sync)/],
  },
];

function planOf(db: DatabaseSync, q: RecordedQuery): string {
  return (
    db.prepare(`EXPLAIN QUERY PLAN ${q.sql}`).all(...(q.args as SQLInputValue[])) as {
      detail: string;
    }[]
  )
    .map((row) => row.detail)
    .join('\n');
}

describe('the activity page probes are served by their own indexes', () => {
  let store: OwnedTempStore;
  let raw: DatabaseSync;
  let statsStatements: RecordedQuery[];
  let listStatements: RecordedQuery[];
  let detailStatements: RecordedQuery[];

  beforeAll(() => {
    store = createTempStore('aka-activity-probe-plans-', { migrated: true });
    raw = corpusConnection(store.open());
    const corpus = seedActivityCorpus(raw, { captures: CORPUS_CAPTURES });
    const recorded: RecordedQuery[] = [];
    const activity = new SqliteActivityRepository(
      recordingConnection(raw, recorded),
      () => corpus.endsAt,
    );
    void activity.stats('UTC');
    statsStatements = [...recorded];
    recorded.length = 0;
    void activity.listSessions({
      from: new Date(corpus.endsAt - 7 * DAY_MS).toISOString(),
      excludeEmpty: true,
      limit: 100,
    });
    listStatements = [...recorded];
    recorded.length = 0;
    void activity.getSession(corpus.largestSessionId);
    detailStatements = [...recorded];
  });

  afterAll(() => {
    store.destroy();
  });

  const cases: readonly [string, readonly Probe[], () => RecordedQuery[]][] = [
    ['stats', STATS_PROBES, () => statsStatements],
    ['listSessions', LIST_PROBES, () => listStatements],
    ['getSession', DETAIL_PROBES, () => detailStatements],
  ];

  for (const [read, probes, statements] of cases) {
    for (const probe of probes) {
      it(`${read}: ${probe.name} is read through its index`, () => {
        const matches = statements().filter((q) => probe.statement(q.sql));
        expect(matches, `${read} issued no ${probe.name} statement`).toHaveLength(1);
        const [q] = matches;
        if (!q) throw new Error('unreachable: length asserted above');
        const plan = planOf(raw, q);
        for (const fragment of probe.mustUse) {
          expect(plan, `${probe.name} plan lacks ${String(fragment)}:\n${plan}`).toMatch(fragment);
        }
        for (const fragment of probe.mustNotUse) {
          expect(plan, `${probe.name} plan still walks ${String(fragment)}:\n${plan}`).not.toMatch(
            fragment,
          );
        }
      });
    }
  }
});
