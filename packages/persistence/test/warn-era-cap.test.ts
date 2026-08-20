import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { capWarnEraEnforcementOnce } from '../src/warn-era-cap.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-warn-era-cap-', { migrated: true });

describe('capWarnEraEnforcementOnce', () => {
  it('is a no-op for a redact-era store, no marker written', () => {
    const db = store.open();
    db.policies.upsertCategoryAction('secret', 'block');
    const result = capWarnEraEnforcementOnce(db, 'redact', store.dataDir);
    expect(result).toEqual({ capped: 0, skipped: 'not-warn' });
    expect(db.policies.getCategoryAction('secret')).toBe('block');
    expect(existsSync(join(store.dataDir, 'warn-era-capped'))).toBe(false);
  });

  it('caps a warn-era store once and writes the marker', () => {
    const db = store.open();
    db.policies.upsertCategoryAction('secret', 'block');
    const result = capWarnEraEnforcementOnce(db, 'warn', store.dataDir);
    expect(result).toEqual({ capped: 1 });
    expect(db.policies.getCategoryAction('secret')).toBe('warn');
    expect(existsSync(join(store.dataDir, 'warn-era-capped'))).toBe(true);
  });

  it('never runs twice, even if a fresh block row appears after the marker exists', () => {
    const db = store.open();
    db.policies.upsertCategoryAction('secret', 'block');
    capWarnEraEnforcementOnce(db, 'warn', store.dataDir);
    db.policies.upsertCategoryAction('pii', 'redact');

    const second = capWarnEraEnforcementOnce(db, 'warn', store.dataDir);

    expect(second).toEqual({ capped: 0, skipped: 'already-run' });
    expect(db.policies.getCategoryAction('pii')).toBe('redact'); // untouched
  });
});
