import { DatabaseSync } from 'node:sqlite';

import { deriveFindingStatus, EventKind } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { derivedFindingStatusSql } from '../../src/repositories/resolution-sql.ts';

// Exhaustively cross every EventKind member (plus a non-capture kind, since
// audit_events also carries structural rows) with every finding-key state and
// every latest-resolution-status state, and require the SQL fragment to agree
// with `deriveFindingStatus` — the one shared classifier — on every tuple.
// Sampling would miss exactly the corner this pins: an empty-string finding
// key is not null in either language, but only a test that drives it proves
// SQL's `IS NULL` and JS's `=== null` agree on that.

const EVENT_KINDS: readonly string[] = [...EventKind.options, 'tool_call'];
const FINDING_KEYS: readonly (string | null)[] = [null, '', 'k-1'];
const LATEST_STATUSES: readonly (string | null)[] = [
  null,
  'resolved',
  'dismissed',
  'open',
  'other',
];

function runFragment(
  db: DatabaseSync,
  kind: string,
  findingKey: string | null,
  latestStatus: string | null,
): string {
  const stmt = db.prepare(
    `SELECT ${derivedFindingStatusSql('e', 'f', 'latest.status')} AS s
       FROM (SELECT :kind AS event_type) e,
            (SELECT :key AS finding_key) f,
            (SELECT :latest AS status) latest`,
  );
  const row = stmt.get({ kind, key: findingKey, latest: latestStatus }) as { s: string };
  return row.s;
}

describe('derivedFindingStatusSql', () => {
  it('agrees with deriveFindingStatus on every (kind, findingKey, latestStatus) tuple', () => {
    const db = new DatabaseSync(':memory:');
    try {
      let tupleCount = 0;
      for (const kind of EVENT_KINDS) {
        for (const findingKey of FINDING_KEYS) {
          for (const latestStatus of LATEST_STATUSES) {
            tupleCount += 1;
            const expected = deriveFindingStatus({
              kind,
              findingKey,
              latestResolutionStatus: latestStatus,
            });
            const actual = runFragment(db, kind, findingKey, latestStatus);
            expect(
              actual,
              `kind=${kind} findingKey=${JSON.stringify(findingKey)} latestStatus=${JSON.stringify(latestStatus)}`,
            ).toBe(expected);
          }
        }
      }
      // 4 EventKind members + 1 non-capture kind = 5, times 3 finding-key
      // states, times 5 latest-status states.
      expect(tupleCount).toBe(EVENT_KINDS.length * FINDING_KEYS.length * LATEST_STATUSES.length);
      expect(tupleCount).toBe(75);
    } finally {
      db.close();
    }
  });

  it('the CASE is total: never NULL for any tuple', () => {
    const db = new DatabaseSync(':memory:');
    try {
      for (const kind of EVENT_KINDS) {
        for (const findingKey of FINDING_KEYS) {
          for (const latestStatus of LATEST_STATUSES) {
            const actual = runFragment(db, kind, findingKey, latestStatus);
            expect(actual).not.toBeNull();
          }
        }
      }
    } finally {
      db.close();
    }
  });
});
