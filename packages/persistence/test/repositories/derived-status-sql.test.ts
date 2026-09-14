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
  latestStatusExpr = 'latest.status',
): string {
  const stmt = db.prepare(
    `SELECT ${derivedFindingStatusSql('e', 'f', latestStatusExpr)} AS s
       FROM (SELECT :kind AS event_type) e,
            (SELECT :key AS finding_key) f,
            (SELECT :latest AS status) latest`,
  );
  const row = stmt.get({ kind, key: findingKey, latest: latestStatus }) as { s: string };
  return row.s;
}

function describeTuple(kind: string, findingKey: string | null, latestStatus: string | null) {
  return `kind=${kind} findingKey=${JSON.stringify(findingKey)} latestStatus=${JSON.stringify(latestStatus)}`;
}

describe('derivedFindingStatusSql', () => {
  it('agrees with deriveFindingStatus on every (kind, findingKey, latestStatus) tuple', () => {
    const db = new DatabaseSync(':memory:');
    try {
      const produced = new Set<string>();
      for (const kind of EVENT_KINDS) {
        for (const findingKey of FINDING_KEYS) {
          for (const latestStatus of LATEST_STATUSES) {
            const expected = deriveFindingStatus({
              kind,
              findingKey,
              latestResolutionStatus: latestStatus,
            });
            const actual = runFragment(db, kind, findingKey, latestStatus);
            expect(actual, describeTuple(kind, findingKey, latestStatus)).toBe(expected);
            produced.add(actual);
          }
        }
      }
      // Every result the CASE can return was returned. A tuple count cannot
      // show that: all three input lists are non-empty by construction, so the
      // count always equals their product. An input set that stops reaching an
      // arm (no 'dismissed' latest status, say) fails here instead of agreeing
      // with the classifier on the arms it still reaches.
      expect(produced).toEqual(
        new Set([
          FindingStatus.enum.handled,
          FindingStatus.enum.open,
          FindingStatus.enum.resolved,
          FindingStatus.enum.dismissed,
        ]),
      );
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

  // latestStatusExpr may be a correlated subquery, so each evaluation is a
  // lookup over finding_resolution. The probe is non-deterministic, so SQLite
  // can neither fold nor share its calls, and the call count is exactly how
  // many times the CASE evaluated the expression for one row.
  it('evaluates latestStatusExpr once on a row that reaches it, and never on one that does not', () => {
    const db = new DatabaseSync(':memory:');
    try {
      let calls = 0;
      db.function('probe', { deterministic: false }, (value) => {
        calls += 1;
        return value;
      });
      let rowsReachingLookup = 0;
      let rowsSkippingLookup = 0;
      for (const kind of EVENT_KINDS) {
        for (const findingKey of FINDING_KEYS) {
          for (const latestStatus of LATEST_STATUSES) {
            calls = 0;
            const actual = runFragment(db, kind, findingKey, latestStatus, 'probe(latest.status)');
            const reachesLookup = kind === EventKind.enum.code_change && findingKey !== null;
            rowsReachingLookup += reachesLookup ? 1 : 0;
            rowsSkippingLookup += reachesLookup ? 0 : 1;
            const tuple = describeTuple(kind, findingKey, latestStatus);
            expect(calls, tuple).toBe(reachesLookup ? 1 : 0);
            expect(actual, tuple).toBe(
              deriveFindingStatus({ kind, findingKey, latestResolutionStatus: latestStatus }),
            );
          }
        }
      }
      // Both kinds of row were driven, so neither half of `toBe(reachesLookup ? 1 : 0)`
      // held vacuously.
      expect(rowsReachingLookup).toBeGreaterThan(0);
      expect(rowsSkippingLookup).toBeGreaterThan(0);
    } finally {
      db.close();
    }
  });
});
