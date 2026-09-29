/**
 * A dismissal selects its keys inside the transaction that writes them.
 *
 * `dismissOpenFindingsForRule` reads one rule's open finding keys and writes a
 * `dismissed` row for each. If the read ran outside the write's transaction, a
 * scan could commit `resolved` for one of those keys in between, and the
 * dismissal's later row would supersede it — a finding the scanner had recorded
 * as fixed would read as open again.
 *
 * node:sqlite is synchronous, so a second handle on this thread cannot act
 * "between" two statements on its own. The test puts it there: it intercepts
 * the key select on the dismissing handle and, while that select runs, has a
 * second handle try to commit a resolution for the same key. Under the fix the
 * dismissing handle already holds the write lock, so that commit is refused
 * with SQLITE_BUSY and the key's latest row is the dismissal alone.
 */
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { type LocalDatabase, UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import type { ResolutionInput } from '../../src/repositories/resolutions.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { primaryCode, SQLITE_BUSY } from '../helpers/fault-injection.ts';
import { withTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';
import { withTwoWriters } from '../helpers/with-two-writers.ts';

const RULE = 'secrets/aws-access-key';

function seedAtRest(db: LocalDatabase, findingKey: string): void {
  const event = captureEvent({ kind: 'code_change' });
  db.recordCapture(event, [{ ...captureFinding(event.id, { ruleId: RULE }), findingKey }]);
}

/**
 * Run `during` while `raw` executes the dismissal's key select, and report
 * whether the select was reached at all — without that, a test whose hook never
 * fired would pass on whatever `during` did not do.
 */
function onKeySelect(raw: DatabaseSync, during: () => void): { reached: () => boolean } {
  let reached = false;
  const prepare = raw.prepare.bind(raw);
  raw.prepare = (sql: string): StatementSync => {
    const stmt = prepare(sql);
    // Both fragments: the resolutions repository's own key reads share the
    // first, and only the dismissal's select filters on a rule.
    if (!sql.includes('SELECT DISTINCT f.finding_key AS finding_key')) return stmt;
    if (!sql.includes('d.rule_id = :ruleId')) return stmt;
    const all = stmt.all.bind(stmt);
    stmt.all = ((...args: Parameters<StatementSync['all']>) => {
      const rows = all(...args);
      reached = true;
      during();
      return rows;
    }) as StatementSync['all'];
    return stmt;
  };
  return { reached: () => reached };
}

describe('dismissOpenFindingsForRule', () => {
  it('holds the write lock while it reads the keys, so a concurrent resolve cannot land in between', () => {
    withTwoWriters((dismisser, scanner) => {
      seedAtRest(dismisser, 'k-1');

      // The scanner gives up at once rather than waiting out busy_timeout on a
      // lock this same thread holds.
      scanner[UNSAFE_TEST_ONLY_RAW_HANDLE].exec('PRAGMA busy_timeout = 0');

      let refusal: unknown;
      const hook = onKeySelect(dismisser[UNSAFE_TEST_ONLY_RAW_HANDLE], () => {
        try {
          scanner.resolutions.insertResolution({
            findingKey: 'k-1',
            status: 'resolved',
            method: 'fixed-at-source',
            resolvedAt: Date.now(),
            evidence: '',
          });
        } catch (err) {
          refusal = err;
        }
      });

      const dismissed = dismisser.dismissOpenFindingsForRule(RULE, {
        method: 'acknowledged',
        resolvedAt: Date.now(),
        evidence: '',
      });

      expect(hook.reached()).toBe(true);
      expect(primaryCode(refusal)).toBe(SQLITE_BUSY);
      expect(dismissed).toBe(1);
      expect(scanner.resolutions.latestByKey('k-1')?.status).toBe('dismissed');
      assertNoOpenTransaction(dismisser[UNSAFE_TEST_ONLY_RAW_HANDLE]);
    });
  });

  it('throws when it cannot take the write lock, and leaves nothing behind', () => {
    withTwoWriters((dismisser, scanner) => {
      seedAtRest(dismisser, 'k-1');
      const dismisserRaw = dismisser[UNSAFE_TEST_ONLY_RAW_HANDLE];
      const scannerRaw = scanner[UNSAFE_TEST_ONLY_RAW_HANDLE];
      // Refuse at once rather than waiting out busy_timeout on a lock this same
      // thread holds through the other handle.
      dismisserRaw.exec('PRAGMA busy_timeout = 0');

      scannerRaw.exec('BEGIN IMMEDIATE');
      let refusal: unknown;
      try {
        dismisser.dismissOpenFindingsForRule(RULE, {
          method: 'acknowledged',
          resolvedAt: Date.now(),
          evidence: '',
        });
      } catch (err) {
        refusal = err;
      } finally {
        scannerRaw.exec('ROLLBACK');
      }

      // A dismissal the store refused must surface, never read as "nothing to
      // do" — the action would otherwise report a refused write as done.
      expect(primaryCode(refusal)).toBe(SQLITE_BUSY);
      assertNoOpenTransaction(dismisserRaw);
      expect(scanner.resolutions.latestByKey('k-1')).toBeUndefined();
      // The control: with the lock released the same call writes, so the
      // refusal above was the lock and not a store with nothing to dismiss.
      expect(
        dismisser.dismissOpenFindingsForRule(RULE, {
          method: 'acknowledged',
          resolvedAt: Date.now(),
          evidence: '',
        }),
      ).toBe(1);
    });
  });

  it('writes the dismissal and the selected key even when handed a wider object', () => {
    withTempStore((store) => {
      const db = store.open();
      seedAtRest(db, 'k-1');
      // A full resolution held in a variable satisfies the narrower parameter
      // type — excess-property checks apply only to literals — so its own
      // `status` and `findingKey` must not reach the write.
      const wider: ResolutionInput = {
        findingKey: 'k-elsewhere',
        status: 'resolved',
        method: 'acknowledged',
        resolvedAt: 1,
        evidence: '',
      };

      expect(db.dismissOpenFindingsForRule(RULE, wider)).toBe(1);
      expect(db.resolutions.latestByKey('k-1')?.status).toBe('dismissed');
      expect(db.resolutions.latestByKey('k-elsewhere')).toBeUndefined();
    });
  });

  it('writes one dismissed row per open key of the rule and nothing for another rule', () => {
    withTempStore((store) => {
      const db = store.open();
      seedAtRest(db, 'k-1');
      seedAtRest(db, 'k-2');

      expect(
        db.dismissOpenFindingsForRule(RULE, {
          method: 'false-positive',
          resolvedAt: 1,
          evidence: '{}',
        }),
      ).toBe(2);
      expect(db.resolutions.latestByKey('k-1')).toEqual({
        status: 'dismissed',
        method: 'false-positive',
        resolvedAt: 1,
        evidence: '{}',
      });
      expect(db.resolutions.latestByKey('k-2')?.status).toBe('dismissed');
      // Nothing left to dismiss: the keys just written are no longer open.
      expect(
        db.dismissOpenFindingsForRule(RULE, {
          method: 'acknowledged',
          resolvedAt: 2,
          evidence: '',
        }),
      ).toBe(0);
      expect(
        db.dismissOpenFindingsForRule('other/rule', {
          method: 'acknowledged',
          resolvedAt: 2,
          evidence: '',
        }),
      ).toBe(0);
    });
  });
});
