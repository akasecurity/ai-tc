import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';
import { migratedStore } from './helpers/store-templates.ts';

const ENV_RULE = Rule.parse(
  JSON.parse(
    readFileSync(resolve(__dirname, '../../../rules/secrets-infra/env-key-value.json'), 'utf8'),
  ),
);

// Built at runtime so no credential-shaped literal sits in this file.
const VALUE = ['not', 'a', 'real', 'value', '77'].join('-');
const NAME = ['STRIPE', 'SECRET', 'KEY'].join('_');
const EQ = String.fromCharCode(61);

let root: string;
let store: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-fs-scan-name-'));
  store = mkdtempSync(join(tmpdir(), 'aka-fs-scan-name-db-'));
  migratedStore.seed(store);
});

afterEach(() => {
  removeTrees([root, store]);
});

describe('scanPathIntoStore — variable name', () => {
  it('stores the variable an env-style secret is assigned to, and never the value', async () => {
    writeFileSync(join(root, 'deploy.sh'), ['export ', NAME, EQ, '"', VALUE, '"\n'].join(''));
    const db = openLocalDatabase(store);
    try {
      const result = await scanPathIntoStore(db, root, { rules: [ENV_RULE] });
      expect(result.files[0]?.findings[0]?.variableName).toBe(NAME);
      const [view] = await db.findings.recentFindings({ limit: 1 });
      expect(view?.variableName).toBe(NAME);
    } finally {
      db.close();
    }
    const raw = new DatabaseSync(join(store, DB_FILENAME), { readOnly: true });
    try {
      const rows = raw
        .prepare('SELECT variable_name, masked_match FROM inspection_findings')
        .all() as { variable_name: string | null; masked_match: string }[];
      expect(rows.map((r) => r.variable_name)).toEqual([NAME]);
      expect(JSON.stringify(rows)).not.toContain(VALUE);
    } finally {
      raw.close();
    }
  });
});
