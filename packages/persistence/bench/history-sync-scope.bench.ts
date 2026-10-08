/**
 * The history-sync ledger's SCOPED reads beside their machine twins, on the
 * same rows.
 *
 * On a scoped attachment a personal row is never stamped (it has to stay
 * eligible for the day its repository is enrolled), so it stays in the unsent
 * set on every pass. Where the scope is a residual clause, as in the session
 * reads and the counts, every page reads past those rows; the capture reads
 * seek an index of their own by scope key instead. Both kinds are measured
 * here, on a store whose pre-attach backlog is mostly personal, with a few
 * enrolled sessions and captures at the far end of it, at two sizes an order
 * of magnitude apart.
 *
 * THE DELIVERY-STATE COUNTS are measured on a store of their own, with MIXED
 * keys: a session root and its leaves carry different ones, the shape a session
 * that moved between repositories leaves behind. A scoped count tests a
 * structural row's own key and, when that is enrolled, its session root's key
 * through a primary-key probe, so a store keyed one way throughout would never
 * pay for the probe on a row that fails it. Here half the sessions are enrolled
 * leaves under a personal or keyless root, the probe's worst case: those leaves
 * pass the first test and fail the second. Each prompt is longer than a page
 * holds, so reading its key walks an overflow chain, as a long prompt does on a
 * real store. The first store is unchanged, so its rows stay comparable with
 * earlier runs.
 *
 * THE CAPTURE PROBE AND LONG PROMPTS. `scoped.capturesProbe` is the drain's
 * "is anything owed in scope?" question, a limit of one, asked with a key no
 * row carries: the answer is no, and a read can only give it once it has ruled
 * out every row it could have returned. The capture reads run again on a store
 * whose prompts are longer than a page holds (the `-4KB` rows): a row's scope
 * key is read from its attribute bag, which sits after the body, so on a long
 * prompt a read that computes keys walks the body's overflow chain, and short
 * prompts would hide that cost.
 *
 * BEFORE AND AFTER, ON THE SAME ROWS. Against a build that predates a scoped
 * statement, its `scoped.*` case passes a scope list the method ignores, so it
 * runs the machine statement; against one with it, it runs the scoped
 * statement. The `machine.*` cases are the control in both runs. Run this file
 * alone, named as a positional argument:
 *
 *   pnpm --filter @akasecurity/persistence exec vitest bench --run \
 *     --outputJson=bench-results.json bench/history-sync-scope.bench.ts
 *
 * Not the package's `bench` script with `-- <file>`: vitest keeps whatever
 * follows a `--` out of its file filters, so that form runs every bench in the
 * package, not this one.
 *
 * NO ASSERTIONS: a measurement, not a gate. What must HOLD about these reads is
 * asserted as query plans in `test/repositories/history-sync.test.ts`. No
 * store here is ever ANALYZEd: the product never runs it, so the planner plans
 * from schema shape alone here, as it does on a user's machine.
 */
import { bench, describe } from 'vitest';

import type { LocalDatabase } from '../src/database.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/**
 * Sessions per store. In the first store each is personal and carries an owed
 * personal capture; in the second each carries the mixed keys `mixedKeys` gives.
 */
const SCALES = [2_000, 20_000] as const;

/** Enrolled sessions, each with an owed capture, all newer than every other row. */
const ENROLLED = 25;

const WORK = 'github.com/acme/work';
const PERSONAL = 'github.com/someone/dotfiles';
const T0 = Date.parse('2026-08-01T00:00:00.000Z');
const ALL = T0 + 365 * 86_400_000;

/** A prompt body longer than one page holds, so its row's key sits past an overflow chain. */
const LONG_PROMPT = 'x'.repeat(4_096);

const at = (offsetMs: number): string => new Date(T0 + offsetMs).toISOString();

/**
 * A root, an llm_call leaf and an owed prompt, all stamped with `scopeKey`. The
 * prompt's body is `content`: a few bytes unless a store asks for a long one.
 */
function seedSession(
  db: LocalDatabase,
  id: string,
  offsetMs: number,
  scopeKey: string,
  content = `text of ${id}`,
): void {
  const attributes = { scope_key: scopeKey };
  db.auditEvents.insertAuditEvent({
    id,
    eventType: 'session',
    startedAt: at(offsetMs),
    attributes,
  });
  db.auditEvents.insertAuditEvent({
    id: `${id}-llm`,
    eventType: 'llm_call',
    rootSessionId: id,
    parentId: id,
    startedAt: at(offsetMs + 1_000),
    attributes,
  });
  db.auditEvents.insertAuditEvent({
    id: `${id}-prompt`,
    eventType: 'prompt',
    rootSessionId: id,
    parentId: id,
    startedAt: at(offsetMs + 2_000),
    content,
    attributes,
  });
  db.historySync.markCaptureOwed(`${id}-prompt`);
}

/**
 * The keys session `i` of the mixed store carries, cycling four shapes. A root
 * with no key is a stub, or one a build before stamping wrote.
 */
function mixedKeys(i: number): { root: string | undefined; leaves: string } {
  switch (i % 4) {
    case 0:
      // Enrolled leaves under a personal root: probed, and refused by the probe.
      return { root: PERSONAL, leaves: WORK };
    case 1:
      // Enrolled leaves under a keyless root: probed, and refused by the probe.
      return { root: undefined, leaves: WORK };
    case 2:
      // An enrolled root whose leaves are personal.
      return { root: WORK, leaves: PERSONAL };
    default:
      return { root: PERSONAL, leaves: PERSONAL };
  }
}

/** A root keyed `keys.root`; two structural leaves and an owed long prompt keyed `keys.leaves`. */
function seedMixedSession(
  db: LocalDatabase,
  id: string,
  offsetMs: number,
  keys: { root: string | undefined; leaves: string },
): void {
  db.auditEvents.insertAuditEvent({
    id,
    eventType: 'session',
    startedAt: at(offsetMs),
    ...(keys.root === undefined ? {} : { attributes: { scope_key: keys.root } }),
  });
  const attributes = { scope_key: keys.leaves };
  for (const [suffix, eventType, step] of [
    ['llm', 'llm_call', 1],
    ['tool', 'tool_call', 2],
  ] as const) {
    db.auditEvents.insertAuditEvent({
      id: `${id}-${suffix}`,
      eventType,
      rootSessionId: id,
      parentId: id,
      startedAt: at(offsetMs + step * 1_000),
      attributes,
    });
  }
  db.auditEvents.insertAuditEvent({
    id: `${id}-prompt`,
    eventType: 'prompt',
    rootSessionId: id,
    parentId: id,
    startedAt: at(offsetMs + 3_000),
    content: LONG_PROMPT,
    attributes,
  });
  db.historySync.markCaptureOwed(`${id}-prompt`);
}

interface Fixture {
  readonly store: OwnedTempStore;
  readonly db: LocalDatabase;
}

const fixtures = new Map<number, Fixture>();
const mixedFixtures = new Map<number, Fixture>();
const longFixtures = new Map<number, Fixture>();

function fixtureFor(personal: number): LocalDatabase {
  const existing = fixtures.get(personal);
  if (existing) return existing.db;
  const store = createTempStore(`aka-bench-history-scope-${String(personal)}-`, {
    migrated: true,
  });
  const db = store.open();
  db.auditEvents.runInTransaction(() => {
    for (let i = 0; i < personal; i += 1) {
      seedSession(db, `p-${String(i)}`, i * 10_000, PERSONAL);
    }
    for (let i = 0; i < ENROLLED; i += 1) {
      seedSession(db, `w-${String(i)}`, (personal + i) * 10_000, WORK);
    }
  });
  fixtures.set(personal, { store, db });
  return db;
}

function mixedFixtureFor(sessions: number): LocalDatabase {
  const existing = mixedFixtures.get(sessions);
  if (existing) return existing.db;
  const store = createTempStore(`aka-bench-history-counts-${String(sessions)}-`, {
    migrated: true,
  });
  const seeding = store.open();
  seeding.auditEvents.runInTransaction(() => {
    for (let i = 0; i < sessions; i += 1) {
      seedMixedSession(seeding, `m-${String(i)}`, i * 10_000, mixedKeys(i));
    }
    for (let i = 0; i < ENROLLED; i += 1) {
      seedMixedSession(seeding, `w-${String(i)}`, (sessions + i) * 10_000, {
        root: WORK,
        leaves: WORK,
      });
    }
  });
  seeding.close();
  // Measured from a fresh handle, opened after the seeding one closed.
  const db = store.open();
  mixedFixtures.set(sessions, { store, db });
  return db;
}

/**
 * The first store's shape with every prompt LONG_PROMPT long, for the capture
 * reads. Measured from a fresh handle, opened after the seeding one closed.
 */
function longFixtureFor(personal: number): LocalDatabase {
  const existing = longFixtures.get(personal);
  if (existing) return existing.db;
  const store = createTempStore(`aka-bench-history-scope-long-${String(personal)}-`, {
    migrated: true,
  });
  const seeding = store.open();
  seeding.auditEvents.runInTransaction(() => {
    for (let i = 0; i < personal; i += 1) {
      seedSession(seeding, `p-${String(i)}`, i * 10_000, PERSONAL, LONG_PROMPT);
    }
    for (let i = 0; i < ENROLLED; i += 1) {
      seedSession(seeding, `w-${String(i)}`, (personal + i) * 10_000, WORK, LONG_PROMPT);
    }
  });
  seeding.close();
  const db = store.open();
  longFixtures.set(personal, { store, db });
  return db;
}

// tinybench has no "after all files" hook, so the stores are removed when the
// process ends. `createTempStore` roots them under the OS temp dir, so a killed
// run leaks a directory the OS reaps rather than anything in the tree.
process.on('exit', () => {
  for (const { store } of [
    ...fixtures.values(),
    ...mixedFixtures.values(),
    ...longFixtures.values(),
  ]) {
    try {
      store.destroy();
    } catch {
      // Teardown of a benchmark fixture; a failure here has nothing to report to.
    }
  }
});

/** A key no row in any store here is stamped with: a scope with nothing owed in it. */
const ABSENT_KEY = 'github.com/nobody/enrolled-nowhere';

/** The capture reads, run on the short-prompt store and again on the long-prompt one. */
const CAPTURE_READS: readonly (readonly [string, (db: LocalDatabase) => unknown])[] = [
  ['machine.captures', (db) => db.historySync.pendingCaptureRows(100, ALL)],
  ['scoped.captures', (db) => db.historySync.pendingCaptureRows(100, ALL, [WORK])],
  // The drain's "is anything owed in scope?" probe, answered no.
  ['scoped.capturesProbe', (db) => db.historySync.pendingCaptureRows(1, ALL, [ABSENT_KEY])],
];

const READS: readonly (readonly [string, (db: LocalDatabase) => unknown])[] = [
  ['machine.sessions', (db) => db.historySync.pendingSessions(25, ALL)],
  ['scoped.sessions', (db) => db.historySync.pendingSessions(25, ALL, [WORK])],
  ...CAPTURE_READS,
];

const COUNT_READS: readonly (readonly [string, (db: LocalDatabase) => unknown])[] = [
  ['machine.counts', (db) => db.historySync.counts(ALL)],
  ['scoped.counts', (db) => db.historySync.counts(ALL, [WORK])],
  ['machine.partition', (db) => db.historySync.partition()],
  ['scoped.partition', (db) => db.historySync.partition([WORK])],
  ['machine.partitionByKind', (db) => db.historySync.partitionByKind()],
  ['scoped.partitionByKind', (db) => db.historySync.partitionByKind([WORK])],
];

const OPTIONS = { time: 2000, iterations: 3 };

for (const personal of SCALES) {
  describe(`history-sync ledger at ${personal.toLocaleString('en-US')} personal sessions`, () => {
    for (const [name, read] of READS) {
      bench(
        `${name}@${String(personal)}`,
        () => {
          read(fixtureFor(personal));
        },
        {
          ...OPTIONS,
          setup: () => {
            fixtureFor(personal);
          },
        },
      );
    }
  });
}

for (const sessions of SCALES) {
  describe(`history-sync counts at ${sessions.toLocaleString('en-US')} mixed-key sessions`, () => {
    for (const [name, read] of COUNT_READS) {
      bench(
        `${name}@${String(sessions)}`,
        () => {
          read(mixedFixtureFor(sessions));
        },
        {
          ...OPTIONS,
          setup: () => {
            mixedFixtureFor(sessions);
          },
        },
      );
    }
  });
}

for (const personal of SCALES) {
  describe(`history-sync capture reads at ${personal.toLocaleString('en-US')} personal sessions, 4 KB prompts`, () => {
    for (const [name, read] of CAPTURE_READS) {
      bench(
        `${name}@${String(personal)}-4KB`,
        () => {
          read(longFixtureFor(personal));
        },
        {
          ...OPTIONS,
          setup: () => {
            longFixtureFor(personal);
          },
        },
      );
    }
  });
}
