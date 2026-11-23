/**
 * A throwaway AKA home and checkout for driving a hook handler in-process,
 * plus the reads the run suites assert against.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';

import { ISSUED_TWILIO_SID } from '../../../../test/helpers/issued-secret.ts';
import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { ruleExample } from './rule-example.ts';

const PAYLOADS = join(dirname(fileURLToPath(import.meta.url)), '..', 'payloads');

export const RULE_ID = 'secrets/twilio-key';
export const FIXTURE = { ...ruleExample(RULE_ID), example: ISSUED_TWILIO_SID };

/** A constructed payload from `test/payloads/`, with fields overridden. */
export function payload(
  event: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const base = JSON.parse(readFileSync(join(PAYLOADS, `${event}.json`), 'utf8')) as Record<
    string,
    unknown
  >;
  return { ...base, ...overrides };
}

export interface TempStore {
  root: string;
  akaHome: string;
  cwd: string;
  seedPolicy(policy: BuiltinPolicyId): void;
  corrupt(): void;
  findingRules(): unknown[];
  eventTypes(): unknown[];
  attributesOf(eventType: string): unknown[];
  cleanup(): void;
}

export function tempStore(prefix = 'aka-cursor-run-'): TempStore {
  const root = mkdtempSync(join(tmpdir(), prefix));
  // Not created here: the handler's own config load creates it, so a case that
  // must not reach the store can assert the directory never appeared.
  const akaHome = join(root, 'aka-home');
  const cwd = join(root, 'checkout');
  mkdirSync(cwd);
  const dbFile = (): string => join(akaHome, 'data', 'aka.db');
  const query = (sql: string, column: string): unknown[] => {
    const db = new DatabaseSync(dbFile(), { readOnly: true });
    try {
      return db
        .prepare(sql)
        .all()
        .map((row) => row[column]);
    } finally {
      db.close();
    }
  };
  return {
    root,
    akaHome,
    cwd,
    seedPolicy(policy) {
      const db = openLocalDatabase(join(akaHome, 'data'));
      try {
        db.installedPacks.recordInventory(bundledDetections());
        db.installedPacks.setPolicy(FIXTURE.namespace, FIXTURE.packId, policy);
      } finally {
        db.close();
      }
    },
    corrupt() {
      const dataDir = join(akaHome, 'data');
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(dbFile(), 'AKA corrupt-store fixture — not a database\n'.repeat(64));
    },
    findingRules: () =>
      query(
        `SELECT d.rule_id FROM inspection_findings f
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id`,
        'rule_id',
      ),
    eventTypes: () => query('SELECT event_type FROM audit_events', 'event_type'),
    attributesOf: (eventType) =>
      query(`SELECT attributes FROM audit_events WHERE event_type = '${eventType}'`, 'attributes'),
    cleanup: () => {
      removeTrees([root]);
    },
  };
}
