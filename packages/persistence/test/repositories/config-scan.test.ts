import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { latestConfigScan } from '../../src/repositories/config-scan.ts';

let db: DatabaseSync;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec(
    `CREATE TABLE audit_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      attributes TEXT
    )`,
  );
});

afterEach(() => {
  db.close();
});

function insert(id: string, eventType: string, startedAt: number, attributes: string | null): void {
  db.prepare(
    'INSERT INTO audit_events (id, event_type, started_at, attributes) VALUES (?, ?, ?, ?)',
  ).run(id, eventType, startedAt, attributes);
}

describe('latestConfigScan', () => {
  it('returns the newest config_scan by started_at, ignoring other event types', () => {
    insert('scan-a', 'config_scan', 1000, '{"errors":0}');
    insert('scan-b', 'config_scan', 3000, null);
    insert('scan-c', 'config_scan', 2000, '{}');
    insert('sess-1', 'session', 9000, null);
    expect(latestConfigScan(db)).toEqual({ id: 'scan-b', started_at: 3000, attributes: null });
  });

  it('breaks a started_at tie by id DESC', () => {
    insert('scan-a', 'config_scan', 5000, null);
    insert('scan-z', 'config_scan', 5000, '{"errors":2}');
    expect(latestConfigScan(db)).toEqual({
      id: 'scan-z',
      started_at: 5000,
      attributes: '{"errors":2}',
    });
  });

  it('returns undefined when no config_scan events exist', () => {
    insert('sess-1', 'session', 1000, null);
    expect(latestConfigScan(db)).toBeUndefined();
  });
});
