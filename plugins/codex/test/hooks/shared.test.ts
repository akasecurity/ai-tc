import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { countFailOpen } from '../../src/hooks/shared.ts';

// A hook calls countFailOpen() with no base, so the home directory is resolved
// on its own path — and `os.homedir()` throws when the platform cannot name
// one. The toggle makes that refusal reachable; every other call in this file
// gets the real function.
const osHome = vi.hoisted(() => ({ refuse: false }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return {
    ...actual,
    homedir: () => {
      if (osHome.refuse) throw new Error('no home directory');
      return actual.homedir();
    },
  };
});

describe('countFailOpen', () => {
  // Called from inside every hook entry's top-level catch. Two things have to
  // hold there and nowhere else matters as much: it must never throw (a throw
  // inside that catch escapes as an uncaught exception and turns a silent
  // allow into a non-zero exit), and it must never print (Codex reads an empty
  // stdout as "no opinion", and one byte would change that).
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-codex-count-fail-open-'));
  });

  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
  });

  it('counts one exit per call under the home it is given, and prints nothing', () => {
    const writeSpy = vi.spyOn(process.stdout, 'write');
    try {
      countFailOpen(base);
      countFailOpen(base);
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      writeSpy.mockRestore();
    }
    expect(readHookFailOpens(join(base, 'data'))).toMatchObject({ failOpens: 2 });
  });

  it('never throws, even where nothing under the home can be written', () => {
    const blocker = join(base, 'not-a-dir');
    writeFileSync(blocker, '');
    expect(() => {
      countFailOpen(join(blocker, 'home'));
    }).not.toThrow();
  });

  it('never throws when the home directory itself cannot be resolved', () => {
    // The production call passes no base, so `dataDir()` asks `os.homedir()`,
    // and that question is asked BEFORE `recordHookFailOpen`'s own guard runs.
    osHome.refuse = true;
    const writeSpy = vi.spyOn(process.stdout, 'write');
    try {
      expect(() => {
        countFailOpen();
      }).not.toThrow();
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      osHome.refuse = false;
      writeSpy.mockRestore();
    }
  });
});
