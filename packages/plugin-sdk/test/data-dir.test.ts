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

  // Derived from the shim's own exports rather than listed by hand, so a binding
  // added to the module is checked the day it lands instead of the day someone
  // remembers to extend this table. `ensureDataDirSync` is the one renamed
  // export — the SDK's spelling of persistence's `ensureLayoutDirSync`.
  const RENAMED: Record<string, string> = { ensureDataDirSync: 'ensureLayoutDirSync' };
  const bindings = Object.keys(shim).sort();
  const at = (mod: object, name: string): unknown => (mod as Record<string, unknown>)[name];

  // Split by what `toBe` can actually prove about each kind, because one name
  // cannot be true of both. For a FUNCTION, `toBe` is reference identity, so it
  // genuinely rules out a local reimplementation — that is what carries
  // persistence's own behavioural coverage (for `ensureDataDir`, the 0700 mkdir
  // and the shared symlink-guarded tighten) onto this package's surface.
  //
  // For a NUMBER it is value equality, and `Object.is(0o700, 0o700)` is true, so
  // no assertion over the values alone can tell persistence's constant from a
  // local `export const DATA_DIR_MODE = 0o700`. Those two are pinned
  // STRUCTURALLY instead, by `declares no mode of its own` below, which reads
  // the module's bytes. Naming this case "not a local copy" would be a title
  // that cannot go red for the reason it states.
  const fnBindings = bindings.filter((n) => typeof at(shim, n) === 'function');
  const valueBindings = bindings.filter((n) => typeof at(shim, n) !== 'function');

  it('splits its whole surface across the two tables below', () => {
    // Both halves are derived, so a binding could fall out of BOTH and every
    // it.each below would simply generate one case fewer — silently, since a
    // table that shrank still passes. This is what makes that loud, and it
    // subsumes the non-empty check: zero exports fails the union too.
    expect([...fnBindings, ...valueBindings].sort()).toEqual(bindings);
    expect(bindings.length).toBeGreaterThan(5);
  });

  it.each(fnBindings)('serves persistence %s, not a local reimplementation', (name) => {
    expect(at(shim, name)).toBe(at(persistence, RENAMED[name] ?? name));
  });

  // Value equality only — see above. `declares no mode of its own` is what rules
  // out a local copy of these.
  it.each(valueBindings)('agrees with persistence %s', (name) => {
    expect(at(shim, name)).toBe(at(persistence, RENAMED[name] ?? name));
  });

  // Equality alone still holds if someone re-declares the same literals here, so
  // pin the shape too: the module states no mode of its own.
  it('declares no mode of its own', () => {
    const source = readFileSync(new URL('../src/data-dir.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/0o[0-7]+/);
    expect(source).toContain("from '@akasecurity/persistence'");
  });
});
