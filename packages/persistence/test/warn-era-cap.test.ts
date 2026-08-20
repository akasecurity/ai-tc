import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { DATA_FILE_MODE } from '../src/paths.ts';
import { capWarnEraEnforcementOnce } from '../src/warn-era-cap.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-warn-era-cap-');

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

  // Nothing repairs this one. Every other owner-only write under ~/.aka is
  // followed by a tighten that would restore the mode on a later pass, so
  // dropping their create mode leaves a window; drop this one and the marker is
  // group/other-readable for good. It carries no secret — it is an ISO
  // timestamp — but it dates the machine's onboarding, and SECURITY.md's
  // at-rest note makes no carve-out for low-sensitivity files.
  it('writes the marker owner-only, with nothing to repair it afterwards', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const db = store.open();
    db.policies.upsertCategoryAction('secret', 'block');

    // The umask only ever CLEARS bits, so under 0o000 the create keeps exactly
    // what it asked for: 0600 with the mode, 0666 without it. Inheriting a
    // runner's own 0o077 would hand back 0600 either way and the case would
    // pass over the very mutant it exists to catch. Process-global, so restored
    // in a `finally`.
    const previous = process.umask(0o000);
    try {
      capWarnEraEnforcementOnce(db, 'warn', store.dataDir);
    } finally {
      process.umask(previous);
    }

    expect(statSync(join(store.dataDir, 'warn-era-capped')).mode & 0o777).toBe(DATA_FILE_MODE);
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
