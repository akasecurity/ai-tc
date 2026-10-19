import {
  existsSync,
  lstatSync,
  lutimesSync,
  mkdirSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  clearSessionAccountState,
  pruneSessionAccountState,
  SESSION_ACCOUNTS_DIRNAME,
  sessionAccountsDir,
} from '../src/session-accounts.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The per-session account state under the data dir: one directory, cleared
// whole whenever the attachment it was written under changes or ends.
const store = useTempStore('aka-session-accounts-');

describe('session-accounts', () => {
  it('lives in one directory under the data dir', () => {
    expect(SESSION_ACCOUNTS_DIRNAME).toBe('session-accounts');
    expect(sessionAccountsDir(store.dataDir)).toBe(join(store.dataDir, 'session-accounts'));
  });

  it('clears the directory and everything in it', () => {
    const dir = sessionAccountsDir(store.dataDir);
    mkdirSync(join(dir, 'nested'), { recursive: true });
    writeFileSync(join(dir, 's-1.log'), '{}\n');
    writeFileSync(join(dir, 's-1.scan.json'), '{}');
    writeFileSync(join(dir, 'nested', 'left-over'), '');

    expect(clearSessionAccountState(store.dataDir)).toBe(true);
    expect(existsSync(dir)).toBe(false);
  });

  it('is not an error when there is nothing to clear', () => {
    expect(clearSessionAccountState(store.dataDir)).toBe(true);
    expect(clearSessionAccountState(join(store.home, 'no-such-dir'))).toBe(true);
  });

  it('removes a symbolic link in its place without touching what it points at', (ctx) => {
    if (process.platform === 'win32') ctx.skip();
    const target = join(store.home, 'elsewhere');
    mkdirSync(target);
    writeFileSync(join(target, 'kept'), 'not session state');
    symlinkSync(target, sessionAccountsDir(store.dataDir));

    expect(clearSessionAccountState(store.dataDir)).toBe(true);
    expect(existsSync(sessionAccountsDir(store.dataDir))).toBe(false);
    expect(existsSync(join(target, 'kept'))).toBe(true);
  });
});

describe('pruneSessionAccountState', () => {
  const NOW = Date.parse('2026-10-14T09:00:00.000Z');
  const DAY = 24 * 60 * 60 * 1000;
  const writtenDaysAgo = (path: string, days: number): void => {
    const at = new Date(NOW - days * DAY);
    utimesSync(path, at, at);
  };

  it('removes a file last written more than thirty days ago, and keeps a newer one', () => {
    const dir = sessionAccountsDir(store.dataDir);
    mkdirSync(dir, { recursive: true });
    const stale = join(dir, 's-old.log');
    const fresh = join(dir, 's-new.scan.json');
    writeFileSync(stale, '{}\n');
    writeFileSync(fresh, '{}');
    writtenDaysAgo(stale, 31);
    writtenDaysAgo(fresh, 29);

    pruneSessionAccountState(store.dataDir, NOW);

    expect(existsSync(stale)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });

  it('leaves a directory or a symbolic link in it, however old', (ctx) => {
    if (process.platform === 'win32') ctx.skip();
    const dir = sessionAccountsDir(store.dataDir);
    const nested = join(dir, 'nested');
    const link = join(dir, 's-link.log');
    mkdirSync(nested, { recursive: true });
    symlinkSync(join(store.home, 'elsewhere'), link);
    writtenDaysAgo(nested, 31);
    const at = new Date(NOW - 31 * DAY);
    lutimesSync(link, at, at);

    pruneSessionAccountState(store.dataDir, NOW);

    expect(existsSync(nested)).toBe(true);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
  });

  it('leaves the files a symbolic link in its place points at, however old', (ctx) => {
    if (process.platform === 'win32') ctx.skip();
    const target = join(store.home, 'elsewhere');
    mkdirSync(target);
    const kept = join(target, 'kept');
    writeFileSync(kept, 'not session state');
    writtenDaysAgo(kept, 31);
    symlinkSync(target, sessionAccountsDir(store.dataDir));

    pruneSessionAccountState(store.dataDir, NOW);

    expect(existsSync(kept)).toBe(true);
  });

  it('is not an error when there is no directory', () => {
    expect(() => {
      pruneSessionAccountState(join(store.home, 'no-such-dir'), NOW);
    }).not.toThrow();
  });
});
