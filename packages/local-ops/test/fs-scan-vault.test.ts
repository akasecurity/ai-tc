import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { LocalDatabase } from '@akasecurity/persistence';
import { applyOnboarding, DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import type { VaultGlue } from '@akasecurity/plugin-sdk';
import { createVaultGlue } from '@akasecurity/plugin-sdk';
import type { ActionTaken, Rule } from '@akasecurity/schema';
import { pointerTokenScanner, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { openScanStoreVault, scanPathIntoStore } from '../src/fs-scan.ts';
import { migratedStore } from './helpers/store-templates.ts';

// Assembled at runtime so no key-shaped literal sits in this file.
const VALUE = ['AK', 'IA'].join('') + 'Q7'.repeat(8);
const OTHER_VALUE = ['AK', 'IA'].join('') + 'Z3'.repeat(8);

const RULES: Rule[] = [
  {
    specVersion: 1,
    id: 'test/aws-key',
    name: 'AWS access key',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'AKIA[0-9A-Z]{16}', flags: 'g' },
  },
];

const REDACTING: ReadonlyMap<string, ActionTaken> = new Map([['test/aws-key', 'redact']]);

interface SightingRow {
  pointer_id: string;
  location: string;
  kind: string;
  first_seen: number;
  last_seen: number;
}

function query<T>(store: string, sql: string): T[] {
  const raw = new DatabaseSync(join(store, DB_FILENAME), { readOnly: true });
  try {
    return raw.prepare(sql).all() as unknown as T[];
  } finally {
    raw.close();
  }
}

const contents = (store: string): string[] =>
  query<{ content: string }>(
    store,
    `SELECT content FROM audit_events WHERE event_type = 'code_change' ORDER BY rowid`,
  ).map((row) => row.content);

const sightings = (store: string): SightingRow[] =>
  query<SightingRow>(
    store,
    'SELECT pointer_id, location, kind, first_seen, last_seen FROM secret_vault_sighting ORDER BY location',
  );

const findingKeys = (store: string): string[] =>
  query<{ finding_key: string }>(store, 'SELECT finding_key FROM inspection_findings').map(
    (row) => row.finding_key,
  );

const pointersIn = (text: string): string[] =>
  [...text.matchAll(pointerTokenScanner())].map((m) => m[0]);

let base: string;
let store: string;
let root: string;
let db: LocalDatabase;
let glue: VaultGlue | undefined;

function grantConsent(): void {
  applyOnboarding(
    { vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION } },
    base,
  );
}

function openGlue(): VaultGlue {
  glue = createVaultGlue({ base, db });
  return glue;
}

async function scan(
  vault: VaultGlue | undefined,
  ruleActions?: ReadonlyMap<string, ActionTaken>,
): Promise<void> {
  await scanPathIntoStore(db, root, {
    rules: RULES,
    dataDir: store,
    vault,
    ...(ruleActions === undefined ? {} : { ruleActions }),
  });
}

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-fs-scan-vault-'));
  store = join(base, 'data');
  mkdirSync(store);
  migratedStore.seed(store);
  root = mkdtempSync(join(tmpdir(), 'aka-fs-scan-vault-root-'));
  db = openLocalDatabase(store);
  glue = undefined;
});

afterEach(() => {
  glue?.close();
  db.close();
  removeTrees([root, base]);
});

describe('scanPathIntoStore — vault', () => {
  it('vaults a detected value once, records a file sighting and stores the pointer in its place', async () => {
    grantConsent();
    const file = join(root, 'settings.env');
    writeFileSync(file, `AWS_KEY=${VALUE}\nREGION=eu\n`);

    await scan(openGlue());

    const rows = db.secretVault.listAll();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.variableName).toBe('AWS_KEY');
    expect(rows[0]?.ruleId).toBe('test/aws-key');

    const [content] = contents(store);
    expect(content).toBeDefined();
    expect(content).not.toContain(VALUE);
    const pointers = pointersIn(content ?? '');
    expect(pointers).toHaveLength(1);
    const pointer = pointers[0] ?? '';
    expect(content).toBe(`AWS_KEY=${pointer}\nREGION=eu\n`);
    expect(pointer.split('.')[1]).toBe(rows[0]?.pointerId);

    expect(sightings(store)).toEqual([
      expect.objectContaining({ pointer_id: rows[0]?.pointerId, location: file, kind: 'file' }),
    ]);
  });

  it('stores the pointer for a span policy also asked to redact', async () => {
    grantConsent();
    writeFileSync(join(root, 'app.ts'), `const a = '${VALUE}';\n`);

    await scan(openGlue(), REDACTING);

    const [content] = contents(store);
    expect(content).not.toContain(VALUE);
    expect(content).not.toContain('[REDACTED:');
    expect(pointersIn(content ?? '')).toHaveLength(1);
  });

  it('keeps finding keys stable and adds no rows or sightings on a re-scan', async () => {
    grantConsent();
    const file = join(root, 'settings.env');
    writeFileSync(file, `AWS_KEY=${VALUE}\n`);

    await scan(undefined);
    const keysBefore = findingKeys(store);

    await scan(openGlue());
    const first = sightings(store);
    await scan(glue);

    expect(findingKeys(store)).toEqual(keysBefore);
    expect(db.secretVault.listAll()).toHaveLength(1);
    const second = sightings(store);
    expect(second).toHaveLength(1);
    expect(second[0]?.pointer_id).toBe(first[0]?.pointer_id);
    expect(second[0]?.first_seen).toBe(first[0]?.first_seen);
    expect(second[0]?.last_seen).toBeGreaterThanOrEqual(first[0]?.last_seen ?? 0);
  });

  it('rewrites the copy stored before consent when the unchanged file is scanned again', async () => {
    writeFileSync(join(root, 'settings.env'), `AWS_KEY=${VALUE}\n`);
    await scan(undefined);
    expect(contents(store)).toEqual([`AWS_KEY=${VALUE}\n`]);

    grantConsent();
    await scan(openGlue());

    const stored = contents(store);
    expect(stored.join('\n')).not.toContain(VALUE);
    expect(stored.every((content) => pointersIn(content).length === 1)).toBe(true);
  });

  it('does not count the stored copy again when it is scanned as a file', async () => {
    grantConsent();
    writeFileSync(join(root, 'settings.env'), `AWS_KEY=${VALUE}\n`);
    await scan(openGlue());
    const [stored] = contents(store);

    const copy = mkdtempSync(join(tmpdir(), 'aka-fs-scan-vault-copy-'));
    try {
      writeFileSync(join(copy, 'stored.env'), stored ?? '');
      const result = await scanPathIntoStore(db, copy, {
        rules: RULES,
        dataDir: store,
        vault: glue,
      });
      expect(result.findings).toBe(0);
      expect(db.secretVault.listAll()).toHaveLength(1);
    } finally {
      removeTrees([copy]);
    }
  });

  it('reuses the row a hook already vaulted for the same value and adds a file sighting', async () => {
    grantConsent();
    const hookGlue = createVaultGlue({ base, db });
    let hookPointer: string;
    try {
      const minted = await hookGlue.tokenizeText(`please use ${VALUE}`, {
        sighting: { location: 'prompt', kind: 'prompt' },
        findings: [
          {
            ruleId: 'test/aws-key',
            category: 'secret',
            severity: 'high',
            rawMatch: VALUE,
            confidence: 0.9,
            span: { start: 11, end: 11 + VALUE.length },
          },
        ],
      });
      hookPointer = minted.pointers[0] ?? '';
    } finally {
      hookGlue.close();
    }
    expect(db.secretVault.listAll()).toHaveLength(1);

    const file = join(root, 'settings.env');
    writeFileSync(file, `AWS_KEY=${VALUE}\n`);
    await scan(openGlue());

    expect(db.secretVault.listAll()).toHaveLength(1);
    expect(pointersIn(contents(store)[0] ?? '')).toEqual([hookPointer]);
    const recorded = sightings(store).map((s) => [s.location, s.kind]);
    expect(recorded).toHaveLength(2);
    expect(recorded).toEqual(
      expect.arrayContaining([
        ['prompt', 'prompt'],
        [file, 'file'],
      ]),
    );
  });

  it('holds one row for a value seen in two files', async () => {
    grantConsent();
    writeFileSync(join(root, 'a.env'), `AWS_KEY=${VALUE}\n`);
    writeFileSync(join(root, 'b.env'), `AWS_KEY=${VALUE}\nOTHER_KEY=${OTHER_VALUE}\n`);

    await scan(openGlue());

    expect(db.secretVault.listAll()).toHaveLength(2);
    const byPointer = new Map<string, string[]>();
    for (const s of sightings(store)) {
      byPointer.set(s.pointer_id, [...(byPointer.get(s.pointer_id) ?? []), s.location]);
    }
    expect([...byPointer.values()].map((locations) => locations.length).sort()).toEqual([1, 2]);
  });

  describe('without vault consent', () => {
    it('mints nothing and stores the file as it stores it today', async () => {
      const text = `AWS_KEY=${VALUE}\n`;
      writeFileSync(join(root, 'settings.env'), text);

      const result = await scanPathIntoStore(db, root, {
        rules: RULES,
        dataDir: store,
        vault: openGlue(),
      });

      expect(result.findings).toBe(1);
      expect(db.secretVault.listAll()).toHaveLength(0);
      expect(sightings(store)).toHaveLength(0);
      expect(contents(store)).toEqual([text]);
    });

    it('still masks a redacted span one-way', async () => {
      writeFileSync(join(root, 'app.ts'), `const a = '${VALUE}';\n`);

      await scan(openGlue(), REDACTING);

      expect(db.secretVault.listAll()).toHaveLength(0);
      expect(contents(store)).toEqual([`const a = '[REDACTED:SECRET]';\n`]);
    });
  });

  describe('openScanStoreVault', () => {
    it('opens no vault without consent', () => {
      expect(openScanStoreVault(db, base)).toBeUndefined();
    });

    it('opens a vault over the given store with consent', async () => {
      grantConsent();
      glue = openScanStoreVault(db, base);
      expect(glue).toBeDefined();
      writeFileSync(join(root, 'settings.env'), `AWS_KEY=${VALUE}\n`);

      await scan(glue);

      expect(db.secretVault.listAll()).toHaveLength(1);
    });
  });

  it('stores the file unchanged when no vault is supplied', async () => {
    grantConsent();
    const text = `AWS_KEY=${VALUE}\n`;
    writeFileSync(join(root, 'settings.env'), text);

    await scan(undefined);

    expect(db.secretVault.listAll()).toHaveLength(0);
    expect(contents(store)).toEqual([text]);
  });
});
