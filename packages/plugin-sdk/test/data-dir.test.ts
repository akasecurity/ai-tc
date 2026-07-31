import { readFileSync } from 'node:fs';

import {
  DATA_DIR_MODE as PERSISTENCE_DIR_MODE,
  DATA_FILE_MODE as PERSISTENCE_FILE_MODE,
} from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

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

  // Equality alone still holds if someone re-declares the same literals here, so
  // pin the shape too: the module states no mode of its own.
  it('declares no mode of its own', () => {
    const source = readFileSync(new URL('../src/data-dir.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/0o[0-7]+/);
    expect(source).toContain("from '@akasecurity/persistence'");
  });
});
