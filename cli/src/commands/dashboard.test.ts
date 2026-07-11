import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { refreshUpdateMirror } from './dashboard.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-dashboard-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

it('pre-launch mirror refresh is fail-open: an unusable store never throws, and names the cause', () => {
  // A FILE where the data dir should be — openLocalDatabase cannot create or
  // open the store here. The refresh must swallow it (launch proceeds) and
  // surface the cause on stderr rather than a bare "(store busy?)" guess.
  const blocked = join(dir, 'blocker');
  writeFileSync(blocked, 'x');
  const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

  expect(() => {
    refreshUpdateMirror(blocked);
  }).not.toThrow();

  const message = stderr.mock.calls.map((c) => String(c[0])).join('');
  expect(message).toContain('could not refresh the detection-update mirror');
  expect(message).toContain('launching anyway');
  expect(message).toMatch(/mirror: \S/); // a concrete cause, not the bare label
});

it('pre-launch mirror refresh records the bundled inventory on a healthy store', () => {
  refreshUpdateMirror(dir);

  const raw = new DatabaseSync(join(dir, 'aka.db'));
  const packs = (raw.prepare('SELECT count(*) AS n FROM available_packs').get() as { n: number }).n;
  raw.close();
  expect(packs).toBeGreaterThan(0); // the bundled packs landed in the mirror
});
