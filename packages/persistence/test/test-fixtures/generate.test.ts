/**
 * The benchmark harness's fixture generator.
 *
 * A benchmark carries no assertions, so everything a bench file would otherwise
 * have checked about its own input has to be checked here instead. Three
 * properties, each of which fails silently in the harness if it breaks:
 *
 *  - **Determinism.** Two runs of the same options must produce the same store.
 *    Without it a nightly trend compares two different corpora and every
 *    movement it reports is noise.
 *  - **The requested size actually lands.** `recordCapture` is fail-open, and
 *    the two dedup gates and the content-addressed capture id each have a way to
 *    collapse a corpus to a fraction of what was asked for. A bench reading a
 *    50-row store instead of a 5,000-row one reports a fast number, not a red
 *    one.
 *  - **The refusal is real.** The size check has to go red when the rows are
 *    missing, or it is decoration.
 *
 * A fourth was added once the corpus grew the axes `/security`'s reads are
 * sensitive to: **the shape has to land, not just the row count.** A corpus can
 * hold every event and finding it promised while carrying no `finding_key` and no
 * resolution row, and three of that page's reads then return NOTHING — while
 * still running, still producing a plan, and still reporting a duration. That is
 * the failure the four separate landed-row checks exist for, and the cases below
 * drive each of them independently, because none implies another.
 */
import type { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import type { CaptureCorpusTarget } from '../../src/test-fixtures/index.ts';
import { createSeededRandom, generateCaptureCorpus } from '../../src/test-fixtures/index.ts';
import { seedCaptureCorpus } from '../helpers/corpus.ts';
import { createTempStore, useTempStore } from '../helpers/temp-store.ts';

const raw = (db: LocalDatabase): DatabaseSync => db[UNSAFE_TEST_ONLY_RAW_HANDLE];

/** Every audit row, in a stable order, as the store holds it. */
const allRows = (db: LocalDatabase): unknown[] =>
  raw(db)
    .prepare(
      'SELECT id, event_type, started_at, content, content_hash, root_session_id ' +
        'FROM audit_events ORDER BY id',
    )
    .all();

const scalar = (db: LocalDatabase, sql: string): number =>
  (raw(db).prepare(sql).get() as { c: number }).c;

const captureCount = (db: LocalDatabase): number =>
  scalar(db, "SELECT COUNT(*) AS c FROM audit_events WHERE event_type <> 'session'");

const findingCount = (db: LocalDatabase): number =>
  scalar(db, 'SELECT COUNT(*) AS c FROM inspection_findings');

/**
 * A second temp store within one test, for the cases that compare two
 * independently generated corpora. `useTempStore` is hook-driven and hands out
 * one store per test, so those cases own theirs — through the same primitive,
 * so the handle and the tree are still cleaned up on the failing path.
 */
function generatedStore(options: Parameters<typeof seedCaptureCorpus>[1]) {
  const owned = createTempStore('aka-corpus-alt-');
  try {
    const db = owned.open();
    seedCaptureCorpus(db, options);
    return { rows: allRows(db), contents: contentColumn(db), count: captureCount(db) };
  } finally {
    owned.destroy();
  }
}

/**
 * The `content` column alone, in GENERATION order — the part of a row that comes
 * only from the PRNG, lined up so two corpora can be compared position by
 * position.
 *
 * Both halves of that are load-bearing, and each was established by a mutation
 * that survived without it.
 *
 * The whole-row comparison cannot tell whether the SEED is doing anything,
 * because the seed reaches a row through two independent channels: the PRNG, and
 * the `contentHash` literal it is interpolated into (which in turn decides the
 * content-addressed capture id). A generator that ignored its seed everywhere
 * except that literal still produced two visibly different stores.
 *
 * Ordering then has to come from something the seed does NOT touch. `id` is the
 * content-addressed capture id, so under that same mutation the two corpora hold
 * the identical set of content strings in two different ORDERS — and an
 * order-sensitive comparison calls that a difference, which is how the first
 * attempt at this projection survived the mutation too. `started_at` is
 * `EPOCH_MS + index * spacing`: unique per event, identical across seeds, and
 * derived from nothing random. Position i in both arrays is therefore the i-th
 * generated event in each, and a difference is a difference in what the PRNG
 * produced.
 */
function contentColumn(db: LocalDatabase): string[] {
  return (
    raw(db)
      .prepare("SELECT content FROM audit_events WHERE event_type <> 'session' ORDER BY started_at")
      .all() as { content: string }[]
  ).map((r) => r.content);
}

describe('createSeededRandom', () => {
  const draw = (seed: number) => Array.from({ length: 8 }, createSeededRandom(seed));

  it('is a pure function of its seed', () => {
    expect(draw(42)).toEqual(draw(42));
  });

  it('produces a different stream per seed', () => {
    // Without this, every "the seed changes the corpus" case below could hold
    // on a generator that ignored its seed entirely.
    expect(draw(42)).not.toEqual(draw(43));
  });

  it('stays inside [0, 1)', () => {
    const rng = createSeededRandom(7);
    for (let i = 0; i < 1_000; i += 1) {
      const v = rng();
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });

  it('is pinned to a value, so a change of algorithm cannot pass silently', () => {
    // A corpus is reproducible across machines and across time only if the
    // generator itself is. Swap mulberry32 for anything else — including a
    // platform primitive that is free to change between releases — and this is
    // what says so.
    expect(createSeededRandom(1)()).toBeCloseTo(0.6270739405881613, 12);
  });
});

describe('generateCaptureCorpus', () => {
  const store = useTempStore('aka-corpus-');

  it('writes exactly the number of capture events asked for', () => {
    const db = store.open();
    const corpus = seedCaptureCorpus(db, { events: 200, sessions: 7 });

    expect(corpus.events).toBe(200);
    // Read it back rather than trusting the return value: the count the
    // generator reports comes from the same query it checks with, so a corpus
    // that never landed would agree with itself.
    expect(captureCount(db)).toBe(200);
  });

  it('spreads events across the requested sessions and plants a root for each', () => {
    const db = store.open();
    seedCaptureCorpus(db, { events: 120, sessions: 6 });

    expect(scalar(db, "SELECT COUNT(*) AS c FROM audit_events WHERE event_type = 'session'")).toBe(
      6,
    );
    expect(
      scalar(
        db,
        "SELECT COUNT(DISTINCT root_session_id) AS c FROM audit_events WHERE event_type <> 'session'",
      ),
    ).toBe(6);
  });

  it('produces identical stores for one seed', () => {
    const options = { events: 150, seed: 99, sessions: 5 } as const;
    const first = generatedStore(options);
    const second = generatedStore(options);

    // Guard the comparison itself: two empty stores are equal, and that would
    // satisfy this case on a generator that wrote nothing.
    expect(first.count).toBe(150);
    expect(second.rows).toEqual(first.rows);
    expect(second.contents).toEqual(first.contents);
  });

  it('produces a different store for a different seed', () => {
    // The control for the case above. Without it, a generator that ignored its
    // options and wrote a constant corpus would pass "identical for one seed"
    // perfectly.
    const first = generatedStore({ events: 150, seed: 99, sessions: 5 });
    const second = generatedStore({ events: 150, seed: 100, sessions: 5 });

    expect(second.rows).not.toEqual(first.rows);
    // The row comparison alone is satisfied by the seed reaching `contentHash`,
    // which it does literally — so it stays green on a generator that seeds its
    // PRNG with a constant. This is the half that does not.
    expect(second.contents).not.toEqual(first.contents);
    expect(first.contents).toHaveLength(150);
  });

  it('gives every event a distinct content hash, so none collapses onto another row', () => {
    const db = store.open();
    seedCaptureCorpus(db, { events: 300, sessions: 3 });

    // The capture row is content-addressed on (sessionId, contentHash,
    // filePath). A shared hash would fold every event in a session onto one
    // row — a 300-event corpus arriving as 3. The size check catches that; this
    // names the reason.
    expect(
      scalar(
        db,
        "SELECT COUNT(DISTINCT content_hash) AS c FROM audit_events WHERE event_type <> 'session'",
      ),
    ).toBe(300);
  });

  it('lands every finding it generates, rather than losing them to session dedup', () => {
    const db = store.open();
    // A rate of 1 across few sessions is exactly the arrangement
    // `(ruleId, maskedMatch, sessionId)` dedup collapses when the masked
    // preview is constant.
    const corpus = seedCaptureCorpus(db, { events: 60, sessions: 2, findingRate: 1 });

    expect(corpus.findings).toBe(60);
    expect(findingCount(db)).toBe(60);
  });

  it('writes no findings at a rate of zero', () => {
    const db = store.open();
    const corpus = seedCaptureCorpus(db, { events: 40, findingRate: 0 });

    expect(corpus.findings).toBe(0);
    expect(findingCount(db)).toBe(0);
  });

  it('adds to a store that already holds a corpus rather than counting it twice', () => {
    const db = store.open();
    seedCaptureCorpus(db, { events: 50, seed: 1, sessions: 4 });
    const second = seedCaptureCorpus(db, { events: 50, seed: 2, sessions: 4 });

    // The size check is a DELTA, not an absolute count. Were it absolute, the
    // second call would see 100 rows against a request for 50 and throw on a
    // corpus that was written perfectly.
    expect(second.events).toBe(50);
    expect(captureCount(db)).toBe(100);
  });

  it('refuses a store where the writes did not land', () => {
    // The positive control for the fail-open guard. `recordCapture` swallows a
    // failed write and returns, so a generator trusting its own calls hands
    // back an empty store and the benchmark reading it reports a fast number. A
    // no-op write is the smallest faithful stand-in for that.
    const db = store.open();
    const target: CaptureCorpusTarget = {
      recordCapture: () => {
        /* swallowed, exactly as a locked or full store does */
      },
      connection: raw(db),
    };

    expect(() => generateCaptureCorpus(target, { events: 25 })).toThrow(
      /wrote 0 capture events, expected 25/,
    );
  });

  it('makes a code_change capture trackable and every other kind not', () => {
    // Mirrors the product: plugin-sdk's runtime sets
    // `isAtRest = kind === 'code_change' && filePath !== undefined` and keys those
    // findings alone. Asserted as a PARTITION rather than a count, because a
    // corpus that keyed every finding would satisfy a bare "some are keyed" check
    // while presenting a store no product path can write — and every read that
    // branches on `finding_key IS NOT NULL` would then be measured on it.
    const db = store.open();
    const corpus = seedCaptureCorpus(db, { events: 600, seed: 3 });
    const split = raw(db)
      .prepare(
        `SELECT e.event_type AS kind,
                SUM(CASE WHEN f.finding_key IS NULL THEN 0 ELSE 1 END) AS keyed,
                SUM(CASE WHEN f.finding_key IS NULL THEN 1 ELSE 0 END) AS unkeyed
           FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
          GROUP BY e.event_type`,
      )
      .all() as { kind: string; keyed: number; unkeyed: number }[];

    // Vacuity: a corpus with no findings on either side of the partition would
    // satisfy every row assertion below.
    expect(corpus.findings, 'corpus produced no findings to partition').toBeGreaterThan(0);
    expect(corpus.trackableFindings).toBeGreaterThan(0);
    expect(corpus.trackableFindings).toBeLessThan(corpus.findings);

    for (const row of split) {
      if (row.kind === 'code_change') {
        expect(row.unkeyed, 'a code_change finding was left unkeyed').toBe(0);
        expect(row.keyed).toBeGreaterThan(0);
      } else {
        expect(row.keyed, `${row.kind} findings must carry no finding_key`).toBe(0);
      }
    }

    // The reported tally is what a caller sizes a measurement against, so it is
    // read back off disk rather than trusted.
    const onDisk = (
      raw(db)
        .prepare('SELECT COUNT(*) AS c FROM inspection_findings WHERE finding_key IS NOT NULL')
        .get() as { c: number }
    ).c;
    expect(corpus.trackableFindings).toBe(onDisk);
  });

  it('gives every code_change capture a file path, and no other kind one', () => {
    // `file_path` is half of captureId's content-addressing and the key of the
    // partial index `idx_audit_code_change_path`, so a corpus without it drives
    // the at-rest path reads against an index holding nothing.
    const db = store.open();
    seedCaptureCorpus(db, { events: 400, seed: 4 });
    const rows = raw(db)
      .prepare(
        `SELECT event_type AS kind,
                SUM(CASE WHEN json_extract(attributes, '$.file_path') IS NULL THEN 0 ELSE 1 END) AS withPath,
                SUM(CASE WHEN json_extract(attributes, '$.file_path') IS NULL THEN 1 ELSE 0 END) AS without
           FROM audit_events
          WHERE event_type IN ('prompt', 'response', 'code_change', 'tool_use')
          GROUP BY event_type`,
      )
      .all() as { kind: string; withPath: number; without: number }[];

    expect(rows.length, 'corpus produced no capture events').toBeGreaterThan(0);
    for (const row of rows) {
      if (row.kind === 'code_change') {
        expect(row.without, 'a code_change capture has no file path').toBe(0);
        expect(row.withPath).toBeGreaterThan(0);
      } else {
        expect(row.withPath, `${row.kind} captures must carry no file path`).toBe(0);
      }
    }
  });

  it('writes resolutions only for trackable findings, and only when asked', () => {
    const db = store.open();
    const none = seedCaptureCorpus(db, { events: 300, seed: 5 });
    // The measured default is zero — the real store holds no resolution rows —
    // so the option has to be the only way to get them.
    expect(none.resolutions).toBe(0);

    const other = createTempStore('aka-generate-res-');
    try {
      const withRes = seedCaptureCorpus(other.open(), {
        events: 300,
        seed: 5,
        resolutionRate: 1,
      });
      expect(withRes.resolutions).toBeGreaterThan(0);
      // At a rate of 1 every trackable finding gets exactly one row, which is
      // also what pins the selection to the TRACKABLE set rather than to all
      // findings — the looser reading would produce `findings` rows here.
      expect(withRes.resolutions).toBe(withRes.trackableFindings);

      const orphans = (
        raw(other.open())
          .prepare(
            `SELECT COUNT(*) AS c FROM finding_resolution r
              WHERE NOT EXISTS (SELECT 1 FROM inspection_findings f
                                 WHERE f.finding_key = r.finding_key)`,
          )
          .get() as { c: number }
      ).c;
      // A resolution keyed to no finding is invisible to every read here (all of
      // them reach resolutions THROUGH a finding), so it would inflate the tally
      // while changing no measurement.
      expect(orphans, 'a resolution was written against a key with no finding').toBe(0);
    } finally {
      other.destroy();
    }
  });

  it('resolves only the keys ITS OWN call minted, not the whole store', () => {
    // The generator is additive, so a bare "every trackable finding" read would
    // pick up an earlier corpus's keys and write resolutions against findings
    // this call never created. The landed-row check cannot catch that on its
    // own: it is a DELTA, and rows written for older keys land inside the delta
    // exactly the same way. Measured before the fix — a second 1,000-event
    // corpus added 76 trackable findings and wrote 148 resolutions.
    const db = store.open();
    const first = seedCaptureCorpus(db, { events: 1_000, seed: 1, resolutionRate: 0 });
    expect(
      first.trackableFindings,
      'first corpus minted no keys to contaminate with',
    ).toBeGreaterThan(0);
    expect(first.resolutions).toBe(0);

    const second = seedCaptureCorpus(db, { events: 1_000, seed: 2, resolutionRate: 1 });
    // At a rate of 1, every key the SECOND call minted gets exactly one row —
    // so the total on disk is that call's trackable count and no more.
    expect(second.resolutions).toBe(second.trackableFindings);

    const onDisk = (
      raw(db).prepare('SELECT COUNT(*) AS c FROM finding_resolution').get() as { c: number }
    ).c;
    expect(onDisk).toBe(second.trackableFindings);

    // The sharper form of the same claim: no resolution may name a key the
    // second call did not mint. Asserted over the store rather than over the
    // tally, because the tally is what the defect kept green.
    const foreign = (
      raw(db)
        .prepare(
          `SELECT COUNT(*) AS c FROM finding_resolution
            WHERE finding_key NOT LIKE 'corpus-key-2-%'`,
        )
        .get() as { c: number }
    ).c;
    expect(foreign, 'a resolution was written against a key from another corpus').toBe(0);
  });

  it('stays deterministic with resolutions on, ids and clock included', () => {
    // The resolution writer mints an id and stamps created_at, so it is a second
    // entropy surface the corpus has to close — and one that a row-count check
    // cannot see, since non-deterministic ids still count correctly.
    const shape = (db: LocalDatabase): unknown[] =>
      raw(db)
        .prepare(
          'SELECT id, finding_key, status, method, resolved_at, created_at ' +
            'FROM finding_resolution ORDER BY id',
        )
        .all();

    const a = createTempStore('aka-generate-det-a-');
    const b = createTempStore('aka-generate-det-b-');
    try {
      const dbA = a.open();
      const dbB = b.open();
      const seeded = seedCaptureCorpus(dbA, { events: 300, seed: 7, resolutionRate: 0.5 });
      seedCaptureCorpus(dbB, { events: 300, seed: 7, resolutionRate: 0.5 });
      expect(seeded.resolutions, 'no resolutions to compare').toBeGreaterThan(0);
      expect(shape(dbA)).toEqual(shape(dbB));
    } finally {
      a.destroy();
      b.destroy();
    }
  });

  it('refuses a store that lost its resolutions, independently of its findings', () => {
    // The positive control for the fourth landed-row check. Findings land
    // normally and the resolution writer's table is emptied underneath it, which
    // is what a fail-open swallow on that insert looks like from here — the
    // events and findings checks both stay green.
    const db = store.open();
    const connection = raw(db);
    // A Proxy, not a spread copy: `DatabaseSync`'s methods live on its prototype,
    // so `{ ...connection }` carries none of them and the generator fails on a
    // missing `exec` long before reaching the check under test — which is this
    // case passing for the wrong reason unless the assertion names the message.
    //
    // Anything not intercepted is re-BOUND to the real target rather than handed
    // back loose. `DatabaseSync` and `StatementSync` are host objects that reject
    // a proxy as their receiver, so an unbound method throws `Illegal invocation`
    // on the first call and an accessor throws at the read — the same reason
    // `test/helpers/query-plans.ts` binds in its own pass-through.
    const bound = (target: object, prop: string | symbol): unknown => {
      const value: unknown = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    };
    const swallowResolutionInserts = new Proxy(connection, {
      get(target, prop) {
        if (prop !== 'prepare') return bound(target, prop);
        return (sql: string) => {
          const stmt = target.prepare(sql);
          if (!sql.trimStart().startsWith('INSERT INTO finding_resolution')) return stmt;
          return new Proxy(stmt, {
            get(statement, statementProp) {
              if (statementProp !== 'run') return bound(statement, statementProp);
              return () => ({ changes: 0, lastInsertRowid: 0 });
            },
          });
        };
      },
    });
    const target: CaptureCorpusTarget = {
      recordCapture: (event, findings) => {
        db.recordCapture(event, findings);
      },
      connection: swallowResolutionInserts,
    };

    expect(() =>
      generateCaptureCorpus(target, { events: 300, seed: 7, resolutionRate: 1 }),
    ).toThrow(/wrote 0 resolutions, expected [1-9]/);
  });

  it('rejects options it cannot honour', () => {
    const db = store.open();
    const target: CaptureCorpusTarget = {
      recordCapture: (event, findings) => {
        db.recordCapture(event, findings);
      },
      connection: raw(db),
    };

    expect(() => generateCaptureCorpus(target, { events: -1 })).toThrow(TypeError);
    expect(() => generateCaptureCorpus(target, { events: 1.5 })).toThrow(TypeError);
    expect(() => generateCaptureCorpus(target, { events: 10, sessions: 0 })).toThrow(TypeError);
    expect(() => generateCaptureCorpus(target, { events: 10, findingRate: 2 })).toThrow(RangeError);
    expect(() => generateCaptureCorpus(target, { events: 10, resolutionRate: 2 })).toThrow(
      RangeError,
    );
    // NaN fails BOTH range comparisons, so a bare range check admits it and the
    // corpus then silently carries no resolutions at all — the one outcome the
    // landed-row checks exist to refuse.
    expect(() => generateCaptureCorpus(target, { events: 10, resolutionRate: NaN })).toThrow(
      RangeError,
    );
  });

  it('leaves no transaction open', () => {
    const db = store.open();
    seedCaptureCorpus(db, { events: 10 });
    expect(raw(db).isTransaction).toBe(false);
  });
});
