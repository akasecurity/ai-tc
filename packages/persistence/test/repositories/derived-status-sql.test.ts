import { DatabaseSync } from 'node:sqlite';

import { deriveFindingStatus, EventKind, FindingStatus } from '@akasecurity/schema';
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
// Every FindingStatus member, then null (a key with no resolution row) and one
// off-enum value standing for the whole class the ELSE arm answers for — the
// column is free text, so that class is real. Taken from the enum rather than
// typed out, the way the fragment's own literals are: a member added to
// FindingStatus, and an arm added for it, is driven here with no edit to this
// file, where a hand-typed list would leave the new arm silently uncovered.
const LATEST_STATUSES: readonly (string | null)[] = [...FindingStatus.options, null, 'other'];

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
      // The whole cross product ran. This is what fails a loop that did not
      // run, which would otherwise pass on zero assertions. No literal count
      // beside it: the spaces are derived, so a correct enum addition grows
      // the product, and a hardcoded total would red on that for no reason.
      expect(tupleCount).toBe(EVENT_KINDS.length * FINDING_KEYS.length * LATEST_STATUSES.length);
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
