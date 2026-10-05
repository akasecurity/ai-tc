/**
 * The history-sync ledger's SCOPED reads beside their machine twins, on the
 * same rows.
 *
 * On a scoped attachment the scope is a residual clause in each read: a personal
 * row is never stamped (it has to stay eligible for the day its repository is
 * enrolled), so it stays in the unsent set on every pass, and every page reads
 * past it. That is the cost measured here: a store whose pre-attach backlog is
 * mostly personal, with a few enrolled sessions and captures at the far end of
 * it, at two sizes an order of magnitude apart.
 *
 * BEFORE AND AFTER, ON THE SAME ROWS. Against a build that predates the scoped
 * statements, the `scoped.*` cases pass a third argument the methods ignore, so
 * they run the machine statement; against one with them, they run the scoped
 * statement. The `machine.*` cases are the control in both runs.
 *
 *   pnpm --filter @akasecurity/persistence bench -- bench/history-sync-scope.bench.ts
 *
 * NO ASSERTIONS: a measurement, not a gate. What must HOLD about these reads is
 * asserted as query plans in `test/repositories/history-sync.test.ts`.
 */
import { bench, describe } from 'vitest';

import type { LocalDatabase } from '../src/database.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/** Personal sessions per store; each also carries an owed personal capture. */
const SCALES = [2_000, 20_000] as const;

/** Enrolled sessions, each with an owed capture, all newer than every personal row. */
const ENROLLED = 25;

const WORK = 'github.com/acme/work';
const PERSONAL = 'github.com/someone/dotfiles';
const T0 = Date.parse('2026-08-01T00:00:00.000Z');
const ALL = T0 + 365 * 86_400_000;

const at = (offsetMs: number): string => new Date(T0 + offsetMs).toISOString();

/** A root, an llm_call leaf and an owed prompt, all stamped with `scopeKey`. */
function seedSession(db: LocalDatabase, id: string, offsetMs: number, scopeKey: string): void {
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
    content: `text of ${id}`,
    attributes,
  });
  db.historySync.markCaptureOwed(`${id}-prompt`);
}

interface Fixture {
  readonly store: OwnedTempStore;
  readonly db: LocalDatabase;
}

const fixtures = new Map<number, Fixture>();

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

// tinybench has no "after all files" hook, so the stores are removed when the
// process ends. `createTempStore` roots them under the OS temp dir, so a killed
// run leaks a directory the OS reaps rather than anything in the tree.
process.on('exit', () => {
  for (const { store } of fixtures.values()) {
    try {
      store.destroy();
    } catch {
      // Teardown of a benchmark fixture; a failure here has nothing to report to.
    }
  }
});

const READS: readonly (readonly [string, (db: LocalDatabase) => unknown])[] = [
  ['machine.sessions', (db) => db.historySync.pendingSessions(25, ALL)],
  ['scoped.sessions', (db) => db.historySync.pendingSessions(25, ALL, [WORK])],
  ['machine.captures', (db) => db.historySync.pendingCaptureRows(100, ALL)],
  ['scoped.captures', (db) => db.historySync.pendingCaptureRows(100, ALL, [WORK])],
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
