/**
 * `classified_data` is the meta model's CLASS dimension: one row per recognized
 * sensitive-data class (`aws_key`, `email_pii`, …), pointed at by inspection
 * findings. Per-occurrence detail — the span, the masked match, the action —
 * lives on the finding and never here, and the id is content-addressed on the
 * class NAME alone, so no secret value reaches it.
 *
 * The repository is write-only — one `upsert`, no reader — so the read half of
 * every round-trip below is SQL. It runs over `UNSAFE_TEST_ONLY_RAW_HANDLE`,
 * the connection the repository itself writes through, rather than a second
 * handle: the foreign-key cases are claims about THAT connection's enforcement,
 * and a second connection would only be answering about itself.
 */
import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { InspectionDefinitionInput } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import { classifiedDataId } from '../../src/ids.ts';
import { errorFrom } from '../helpers/errors.ts';
import { SQLITE_CONSTRAINT_FOREIGNKEY, sqliteErrcode } from '../helpers/fault-injection.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-classified-data-');

let db: LocalDatabase;
let raw: DatabaseSync;

beforeEach(() => {
  db = store.open();
  raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
});

/** The stored shape — `label` and `attributes` are nullable in the DDL. */
interface ClassifiedDataRow {
  id: string;
  class: string;
  label: string | null;
  attributes: string | null;
}

const SELECT_COLUMNS = 'SELECT id, class, label, attributes FROM classified_data';

// All three readers take the connection, defaulted to the one the current test
// opened. `persists across a reopen` closes `db` mid-test, which closes the
// handle `raw` names — so a reader that captured `raw` instead would work
// everywhere except the one test that needs a second connection, and would fail
// there as a closed-handle error rather than an assertion.
function rowById(id: string, conn: DatabaseSync = raw): ClassifiedDataRow | undefined {
  return conn.prepare(`${SELECT_COLUMNS} WHERE id = ?`).get(id) as ClassifiedDataRow | undefined;
}

// The double cast is required here and a single one is not in `rowById`, which
// reads like an inconsistency and is not: `.get()` returns `T | undefined`, and
// the undefined arm gives TypeScript the overlap it needs, where `.all()`
// returns a bare `Record<string, SQLOutputValue>[]` that shares no property with
// this row type. Narrowing it to one cast does not compile (TS2352).
function allRows(conn: DatabaseSync = raw): ClassifiedDataRow[] {
  return conn.prepare(`${SELECT_COLUMNS} ORDER BY class`).all() as unknown as ClassifiedDataRow[];
}

function countRows(table: string, conn: DatabaseSync = raw): number {
  return (conn.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

/** The definition every finding below cites; `name` is the only field varied. */
const DEFINITION: InspectionDefinitionInput = {
  ruleId: 'secrets/aws-access-key',
  version: '1.0.0',
  name: 'AWS access key',
  category: 'secret',
  severity: 'critical',
  definition: '{"matcher":"regex"}',
};

describe('SqliteClassifiedDataRepository (via LocalDatabase.classifiedData)', () => {
  it('round-trips a class with its label and attribute bag', () => {
    const id = db.classifiedData.upsert({
      class: 'aws_key',
      label: 'AWS key',
      attributes: { pack: 'core-secrets', severity_hint: 'critical' },
    });

    expect(id).toBe(classifiedDataId('aws_key'));
    const row = rowById(id);
    expect(row).toBeDefined();
    expect(row?.class).toBe('aws_key');
    expect(row?.label).toBe('AWS key');
    // The bag is stored as JSON text, so assert the parsed value: a writer that
    // stringified twice, or dropped a key, still reads back as a string.
    expect(JSON.parse(row?.attributes ?? 'null')).toEqual({
      pack: 'core-secrets',
      severity_hint: 'critical',
    });
    expect(countRows('classified_data')).toBe(1);
  });

  // Both optional columns go through `bindParams`, whose whole job is turning
  // `undefined` into SQL NULL — node:sqlite rejects `undefined` outright, and a
  // writer that reached for a fallback string instead would store the literal
  // text "undefined" and read back as a perfectly valid row.
  it('stores SQL NULL for an omitted label and attribute bag', () => {
    const id = db.classifiedData.upsert({ class: 'email_pii' });

    const row = rowById(id);
    expect(row?.class).toBe('email_pii');
    expect(row?.label).toBeNull();
    expect(row?.attributes).toBeNull();
  });

  it('mints one row and one id per class', () => {
    const ids = ['aws_key', 'email_pii', 'private_key'].map((cls) =>
      db.classifiedData.upsert({ class: cls, label: cls }),
    );

    expect(new Set(ids).size).toBe(3);
    expect(ids).toEqual(['aws_key', 'email_pii', 'private_key'].map(classifiedDataId));
    expect(allRows().map((r) => r.class)).toEqual(['aws_key', 'email_pii', 'private_key']);
  });

  it('persists across a reopen', () => {
    const id = db.classifiedData.upsert({
      class: 'aws_key',
      label: 'AWS key',
      attributes: { pack: 'core-secrets' },
    });
    db.close();

    const reopened = store.open();
    const row = rowById(id, reopened[UNSAFE_TEST_ONLY_RAW_HANDLE]);
    expect(row?.class).toBe('aws_key');
    expect(row?.label).toBe('AWS key');
    expect(JSON.parse(row?.attributes ?? 'null')).toEqual({ pack: 'core-secrets' });
  });
});

/**
 * The id is `sha256(canonicalIdentity(['classified_data', class]))` — the class
 * NAME and nothing else. That is a privacy property, not just a dedup one: the
 * label and the attribute bag are caller-supplied and could carry a sample
 * value, so folding either into the id would put caller text inside a
 * content-addressed key that is copied onto every finding that cites the class.
 */
describe('content addressing', () => {
  it('keys the id on the class alone — a different label or bag does not move it', () => {
    const first = db.classifiedData.upsert({
      class: 'aws_key',
      label: 'AWS key',
      attributes: { pack: 'core-secrets' },
    });
    const second = db.classifiedData.upsert({
      class: 'aws_key',
      label: 'a completely different label',
      attributes: { pack: 'somewhere-else', extra: 'field' },
    });

    expect(second).toBe(first);
    expect(second).toBe(classifiedDataId('aws_key'));
  });

  it('separates two classes whose labels and bags are identical', () => {
    // Equal by value, and a fresh bag per call rather than one object spread
    // twice: sharing the reference would let a repository that mutated or
    // retained its caller's bag pass a test whose whole subject is that the two
    // classes stay apart.
    const shared = (): { label: string; attributes: Record<string, string> } => ({
      label: 'same label',
      attributes: { pack: 'same-pack' },
    });
    const a = db.classifiedData.upsert({ class: 'aws_key', ...shared() });
    const b = db.classifiedData.upsert({ class: 'gcp_key', ...shared() });

    expect(a).not.toBe(b);
    expect(countRows('classified_data')).toBe(2);
  });
});

/**
 * The statement is `INSERT OR IGNORE`, so a repeat class is a no-op rather than
 * an overwrite — and because `label`/`attributes` sit OUTSIDE the id, "no-op"
 * has an observable consequence: the FIRST writer's values are the ones that
 * survive. That is the convention of the package's other content-addressed
 * dimension whose payload is not part of its key (`inspection_definitions`),
 * and deliberately not that of the Type-1 dimensions (`source_project`,
 * `inventory`), which are `ON CONFLICT DO UPDATE` overwrite-to-latest.
 */
describe('duplicate id handling', () => {
  it('re-upserting the same class returns the same id and leaves one row', () => {
    const first = db.classifiedData.upsert({ class: 'aws_key', label: 'AWS key' });
    const second = db.classifiedData.upsert({ class: 'aws_key', label: 'AWS key' });

    expect(second).toBe(first);
    expect(countRows('classified_data')).toBe(1);
  });

  it('ignores a conflicting re-upsert: the first label and bag survive', () => {
    const id = db.classifiedData.upsert({
      class: 'aws_key',
      label: 'AWS key',
      attributes: { pack: 'core-secrets' },
    });
    db.classifiedData.upsert({
      class: 'aws_key',
      label: 'OVERWRITTEN',
      attributes: { pack: 'overwritten' },
    });

    const row = rowById(id);
    expect(row?.label).toBe('AWS key');
    expect(JSON.parse(row?.attributes ?? 'null')).toEqual({ pack: 'core-secrets' });
    expect(countRows('classified_data')).toBe(1);
  });

  // Asserted side by side rather than described in a comment: if either
  // dimension moves to `INSERT OR REPLACE` / `DO UPDATE`, this is the case that
  // says the two no longer agree, whichever one moved.
  it('agrees with the sibling INSERT OR IGNORE dimension (inspection_definitions)', () => {
    const classId = db.classifiedData.upsert({ class: 'aws_key', label: 'first' });
    expect(db.classifiedData.upsert({ class: 'aws_key', label: 'second' })).toBe(classId);

    const definitionId = db.inspectionDefinitions.upsert({ ...DEFINITION, name: 'first' });
    expect(db.inspectionDefinitions.upsert({ ...DEFINITION, name: 'second' })).toBe(definitionId);

    expect({
      classifiedData: rowById(classId)?.label,
      inspectionDefinition: (
        raw.prepare('SELECT name FROM inspection_definitions WHERE id = ?').get(definitionId) as
          { name: string } | undefined
      )?.name,
    }).toEqual({ classifiedData: 'first', inspectionDefinition: 'first' });
  });
});

/**
 * `classified_data` carries no outgoing foreign key of its own — it is a leaf
 * dimension. The constraint that matters is the INBOUND one:
 * `inspection_findings.classified_data_id` references it, so a finding can
 * neither cite a class that was never upserted nor outlive one.
 *
 * On the `foreign_keys = ON` half, be precise about what is and is not pinned
 * here. `openWithPragmas` runs `PRAGMA foreign_keys = ON`, but that line
 * establishes nothing on its own and flipping it to OFF reddens none of the
 * cases below — enforcement survives it twice over. node:sqlite's
 * `DatabaseSync` enables constraints at construction by default
 * (`enableForeignKeyConstraints`), and on a store with a pending table-recreate
 * `applyMigrations` ends by restoring `PRAGMA foreign_keys = ON` in a `finally`
 * whatever the opener asked for. So the check below is a claim about the
 * connection's effective state, not about that pragma statement: it pins that
 * nothing between the open and the first write has turned enforcement OFF,
 * which is exactly what the behavioural cases after it depend on.
 */
describe('foreign keys', () => {
  function seedFindingPrerequisites(): { auditEventId: string; definitionId: string } {
    const auditEventId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: auditEventId,
      eventType: 'prompt',
      startedAt: new Date().toISOString(),
    });
    return { auditEventId, definitionId: db.inspectionDefinitions.upsert(DEFINITION) };
  }

  /** A finding on the seeded event/definition, citing `classId`. */
  function insertFindingCiting(classId: string): void {
    const { auditEventId, definitionId } = seedFindingPrerequisites();
    db.inspectionFindings.insertFinding({
      id: randomUUID(),
      auditEventId,
      inspectionDefinitionId: definitionId,
      classifiedDataId: classId,
      span: { start: 14, end: 34 },
      maskedMatch: 'AKIA…MPLE',
      actionTaken: 'block',
      confidence: 0.9,
    });
  }

  it('enforces foreign keys on the connection the repository writes through', () => {
    expect(raw.prepare('PRAGMA foreign_keys').get()).toEqual({ foreign_keys: 1 });
  });

  it('accepts a finding citing an upserted class', () => {
    const classId = db.classifiedData.upsert({ class: 'aws_key', label: 'AWS key' });

    insertFindingCiting(classId);

    // Bind the row, then read it. Chaining `.get()!.c` would raise a TypeError
    // on an empty table — an unreadable crash where the useful red is
    // "expected undefined to be <id>".
    const row = raw.prepare('SELECT classified_data_id AS c FROM inspection_findings').get() as
      { c: string } | undefined;
    expect(row?.c).toBe(classId);
  });

  it('refuses a finding citing a class that was never upserted', () => {
    // Well-formed, and the id this class WOULD have — it was simply never
    // written. A dangling reference, not a malformed one.
    const err = errorFrom(() => {
      insertFindingCiting(classifiedDataId('never_upserted'));
    });

    // The EXTENDED code, not the primary one and not the message. Primary 19 is
    // shared by UNIQUE (2067) and CHECK (275), so it would not distinguish this
    // refusal from those; the message would, but message text is the engine's
    // to reword. A never-thrown error arrives as undefined, which matches
    // neither, so this still catches a writer that silently accepted the row.
    expect(sqliteErrcode(err)).toBe(SQLITE_CONSTRAINT_FOREIGNKEY);
    expect(countRows('inspection_findings')).toBe(0);
  });

  it('refuses to delete a class a finding still cites', () => {
    const classId = db.classifiedData.upsert({ class: 'aws_key', label: 'AWS key' });
    insertFindingCiting(classId);

    const err = errorFrom(() =>
      raw.prepare('DELETE FROM classified_data WHERE id = ?').run(classId),
    );

    expect(sqliteErrcode(err)).toBe(SQLITE_CONSTRAINT_FOREIGNKEY);
    expect(countRows('classified_data')).toBe(1);
  });

  // An unreferenced class is ordinary data, so the refusal above has to be the
  // FK doing its job rather than the table being undeletable. Without this the
  // case above passes just as well against a DELETE that never works at all.
  it('deletes a class no finding cites', () => {
    const id = db.classifiedData.upsert({ class: 'unreferenced', label: 'nobody cites me' });
    // There has to be a row here for the delete to mean anything: an `upsert`
    // that wrote nothing leaves `err` undefined and the count at 0, so both
    // assertions below would hold over an empty table and this control would
    // go on vouching for the refusal above while proving nothing.
    expect(countRows('classified_data')).toBe(1);

    const err = errorFrom(() => raw.prepare('DELETE FROM classified_data WHERE id = ?').run(id));

    expect(err).toBeUndefined();
    expect(countRows('classified_data')).toBe(0);
  });
});
