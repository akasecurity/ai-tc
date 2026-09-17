import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  hookFailOpensPath,
  readHookFailOpens,
  recordHookFailOpen,
} from '../src/hook-fail-opens.ts';

// Failing open is the ABSENCE of output, so a hook that throws leaves no trace
// the host, the store or the control plane can see. This file is the one
// trace, and everything about it is shaped by being written from inside a
// catch: it must never throw, never print, and never carry the error it counts.
describe('recordHookFailOpen / readHookFailOpens', () => {
  let root: string;
  let dataDir: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-fail-opens-'));
    dataDir = join(root, 'data');
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('reads null before anything was recorded', () => {
    expect(readHookFailOpens(dataDir)).toBeNull();
  });

  it('counts one exit per call and keeps the latest clock', () => {
    recordHookFailOpen(dataDir, 1_000);
    recordHookFailOpen(dataDir, 2_000);
    expect(readHookFailOpens(dataDir)).toEqual({ failOpens: 2, lastAtMs: 2_000 });
  });

  it('creates the data dir and writes the tally owner-only, newline-terminated', () => {
    recordHookFailOpen(dataDir, 1_000);
    // A positive conditional rather than a skip: the newline check below is
    // real on every platform. Windows derives st_mode from a single read-only
    // attribute, so only the mode half is scoped.
    if (process.platform !== 'win32') {
      expect(statSync(hookFailOpensPath(dataDir)).mode & 0o777).toBe(0o600);
    }
    expect(readFileSync(hookFailOpensPath(dataDir), 'utf8')).toMatch(/\}\n$/);
  });

  it.each<[string, string]>([
    ['not json', '{not json'],
    ['a non-object', '[]'],
    ['a zero count', JSON.stringify({ failOpens: 0, lastAtMs: 1 })],
    ['a negative count', JSON.stringify({ failOpens: -3, lastAtMs: 1 })],
    ['a non-numeric count', JSON.stringify({ failOpens: 'many', lastAtMs: 1 })],
    ['a non-finite count', '{"failOpens":1e999,"lastAtMs":1}'],
    ['a non-numeric clock', JSON.stringify({ failOpens: 3, lastAtMs: 'yesterday' })],
  ])('reads %s as nothing recorded', (_label, body) => {
    // Validated rather than trusted: the values are rendered, so a hand-edited
    // or truncated file must produce silence, never an arbitrary line.
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(hookFailOpensPath(dataDir), body);
    expect(readHookFailOpens(dataDir)).toBeNull();
  });

  it('a corrupt tally restarts from one rather than refusing to count', () => {
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(hookFailOpensPath(dataDir), '{not json');
    recordHookFailOpen(dataDir, 5_000);
    expect(readHookFailOpens(dataDir)).toEqual({ failOpens: 1, lastAtMs: 5_000 });
  });

  it('never throws where nothing under the data dir can be written', () => {
    // A FILE in the path blocks mkdir with ENOTDIR regardless of ownership or
    // mode — the reliable fault, since a chmod'd directory is silently
    // re-widened by the owner-only mkdir.
    const blocker = join(root, 'not-a-dir');
    writeFileSync(blocker, '');
    const unwritable = join(blocker, 'data');
    expect(() => {
      recordHookFailOpen(unwritable, 1);
    }).not.toThrow();
    expect(readHookFailOpens(unwritable)).toBeNull();
  });
});
