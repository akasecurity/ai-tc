import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from './database.ts';
import { capWarnEraEnforcementOnce } from './warn-era-cap.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-warn-era-cap-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('capWarnEraEnforcementOnce', () => {
  it('is a no-op for a redact-era store, no marker written', () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'block');
    const result = capWarnEraEnforcementOnce(db, 'redact', dir);
    expect(result).toEqual({ capped: 0, skipped: 'not-warn' });
    expect(db.policies.getCategoryAction('secret')).toBe('block');
    expect(existsSync(join(dir, 'warn-era-capped'))).toBe(false);
    db.close();
  });

  it('caps a warn-era store once and writes the marker', () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'block');
    const result = capWarnEraEnforcementOnce(db, 'warn', dir);
    expect(result).toEqual({ capped: 1 });
    expect(db.policies.getCategoryAction('secret')).toBe('warn');
    expect(existsSync(join(dir, 'warn-era-capped'))).toBe(true);
    db.close();
  });

  it('never runs twice, even if a fresh block row appears after the marker exists', () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'block');
    capWarnEraEnforcementOnce(db, 'warn', dir);
    db.policies.upsertCategoryAction('pii', 'redact');

    const second = capWarnEraEnforcementOnce(db, 'warn', dir);

    expect(second).toEqual({ capped: 0, skipped: 'already-run' });
    expect(db.policies.getCategoryAction('pii')).toBe('redact'); // untouched
    db.close();
  });
});
