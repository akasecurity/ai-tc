import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  columnNames,
  evidenceExists,
  evidenceObjects,
  indexExists,
  schemaObjectExists,
} from '../../../src/db/migrations/introspection.ts';

let db: DatabaseSync;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE events (id TEXT PRIMARY KEY, payload TEXT)');
  db.exec('CREATE INDEX idx_events_payload ON events (payload)');
  db.exec(
    "ALTER TABLE events ADD COLUMN total INTEGER GENERATED ALWAYS AS (json_extract(payload, '$.total')) VIRTUAL",
  );
});

afterEach(() => {
  db.close();
});

describe('schemaObjectExists / indexExists', () => {
  it('finds tables and indexes by kind', () => {
    expect(schemaObjectExists(db, 'table', 'events')).toBe(true);
    expect(schemaObjectExists(db, 'index', 'idx_events_payload')).toBe(true);
    expect(indexExists(db, 'idx_events_payload')).toBe(true);
  });

  it('does not match across kinds or on missing names', () => {
    expect(schemaObjectExists(db, 'index', 'events')).toBe(false);
    expect(schemaObjectExists(db, 'table', 'idx_events_payload')).toBe(false);
    expect(schemaObjectExists(db, 'table', 'missing')).toBe(false);
    expect(indexExists(db, 'missing')).toBe(false);
  });
});

describe('columnNames', () => {
  it('omits generated columns by default (table_info)', () => {
    expect(columnNames(db, 'events')).toEqual(['id', 'payload']);
  });

  it('sees generated columns with includeGenerated (table_xinfo)', () => {
    expect(columnNames(db, 'events', { includeGenerated: true })).toContain('total');
  });

  it('yields an empty list for a missing table', () => {
    expect(columnNames(db, 'missing')).toEqual([]);
    expect(columnNames(db, 'missing', { includeGenerated: true })).toEqual([]);
  });
});

describe('evidenceExists', () => {
  it('probes tables via sqlite_master', () => {
    expect(evidenceExists(db, { kind: 'table', name: 'events' })).toBe(true);
    expect(evidenceExists(db, { kind: 'table', name: 'missing' })).toBe(false);
  });

  it('probes columns generated-aware', () => {
    expect(evidenceExists(db, { kind: 'column', table: 'events', name: 'payload' })).toBe(true);
    expect(evidenceExists(db, { kind: 'column', table: 'events', name: 'total' })).toBe(true);
    expect(evidenceExists(db, { kind: 'column', table: 'events', name: 'missing' })).toBe(false);
    expect(evidenceExists(db, { kind: 'column', table: 'missing', name: 'id' })).toBe(false);
  });
});

describe('evidenceObjects', () => {
  it('extracts created tables and ADDed columns from drizzle-formatted DDL', () => {
    const sql = [
      'CREATE TABLE `alpha` (`id` text PRIMARY KEY NOT NULL);',
      '--> statement-breakpoint',
      'CREATE TABLE IF NOT EXISTS `beta` (`id` text PRIMARY KEY NOT NULL);',
      '--> statement-breakpoint',
      'ALTER TABLE `alpha` ADD `note` text;',
      '--> statement-breakpoint',
      'ALTER TABLE `beta` ADD COLUMN `extra` integer;',
    ].join('\n');
    expect(evidenceObjects(sql)).toEqual([
      { kind: 'table', name: 'alpha' },
      { kind: 'table', name: 'beta' },
      { kind: 'column', table: 'alpha', name: 'note' },
      { kind: 'column', table: 'beta', name: 'extra' },
    ]);
  });

  it('skips transient __new_ recreate tables', () => {
    const sql = [
      'CREATE TABLE `__new_alpha` (`id` text PRIMARY KEY NOT NULL);',
      '--> statement-breakpoint',
      'INSERT INTO `__new_alpha` SELECT * FROM `alpha`;',
      '--> statement-breakpoint',
      'DROP TABLE `alpha`;',
      '--> statement-breakpoint',
      'ALTER TABLE `__new_alpha` RENAME TO `alpha`;',
    ].join('\n');
    expect(evidenceObjects(sql)).toEqual([]);
  });

  it('yields nothing for index-only DDL', () => {
    expect(evidenceObjects('CREATE INDEX `idx_x` ON `alpha` (`id`);')).toEqual([]);
  });
});
