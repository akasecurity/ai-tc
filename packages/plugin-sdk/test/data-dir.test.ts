import { readFileSync } from 'node:fs';

import * as persistence from '@akasecurity/persistence';
import {
  DATA_DIR_MODE as PERSISTENCE_DIR_MODE,
  DATA_FILE_MODE as PERSISTENCE_FILE_MODE,
} from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import * as shim from '../src/data-dir.ts';
import { DATA_DIR_MODE, DATA_FILE_MODE } from '../src/data-dir.ts';

/**
 * `data-dir.ts` is a re-export shim: the ~/.aka layout and its permission modes
 * are defined once, in @akasecurity/persistence, and the SDK modules that write
 * under ~/.aka (throttle.ts, nudge.ts) take them from here. A second definition
 * would drift silently, and the store's only at-rest control would then depend
 * on which module a given writer happened to import.
 */
describe('data-dir re-export', () => {
  it('serves the persistence modes, not a copy', () => {
    expect(DATA_DIR_MODE).toBe(PERSISTENCE_DIR_MODE);
    expect(DATA_FILE_MODE).toBe(PERSISTENCE_FILE_MODE);
  });

  // Every binding here must BE persistence's, not a copy that happens to agree
  // today. Identity is what carries persistence's own behavioural coverage of
  // each one onto this package's surface — for `ensureDataDir` that is the 0700
  // mkdir and the shared, symlink-guarded tighten, which a local
  // reimplementation would satisfy every SDK consumer's import without
  // delivering.
  //
  // Derived from the shim's own exports rather than listed by hand, so a
  // binding added to the module is checked the day it lands instead of the day
  // someone remembers to extend this table. `ensureDataDirSync` is the one
  // renamed export — the SDK's spelling of persistence's `ensureLayoutDirSync`.
  const RENAMED: Record<string, string> = { ensureDataDirSync: 'ensureLayoutDirSync' };
  const bindings = Object.keys(shim).sort();

  it('re-exports a non-empty surface (the table below is derived from it)', () => {
    // Without this the it.each below generates zero cases and passes silently,
    // which is exactly how a shim that stopped re-exporting anything would read.
    expect(bindings.length).toBeGreaterThan(5);
  });

  it.each(bindings)('serves persistence %s, not a local copy', (name) => {
    const source = RENAMED[name] ?? name;
    expect(shim[name as keyof typeof shim]).toBe(persistence[source as keyof typeof persistence]);
  });

  // Equality alone still holds if someone re-declares the same literals here, so
  // pin the shape too: the module states no mode of its own.
  it('declares no mode of its own', () => {
    const source = readFileSync(new URL('../src/data-dir.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/0o[0-7]+/);
    expect(source).toContain("from '@akasecurity/persistence'");
  });
});
