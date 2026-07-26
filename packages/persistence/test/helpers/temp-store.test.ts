import { existsSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createTempStore, useTempStore, withTempStore } from './temp-store.ts';

// The helper's own gate: every store test that adopts it inherits these
// guarantees, so a regression here is a regression in all of them.

describe('withTempStore', () => {
  it('lays the temp tree out like the real home', () => {
    withTempStore((store) => {
      expect(store.settingsDir).toBe(join(store.home, 'settings'));
      expect(store.dataDir).toBe(join(store.home, 'data'));
      expect(store.dbFile).toBe(join(store.home, 'data', 'aka.db'));
    });
  });

  it('opens a usable store under data/', () => {
    withTempStore((store) => {
      const db = store.open();
      db.ruleProbeCache.setVerdict('rule-a', 'safe', 1.5);
      expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({
        verdict: 'safe',
        worstProbeMs: 1.5,
      });
      expect(existsSync(store.dbFile)).toBe(true);
      expect(dirname(store.dbFile)).toBe(store.dataDir);
    });
  });

  it('closes its handles and removes the tree when the body returns', () => {
    let home = '';
    withTempStore((store) => {
      home = store.home;
      store.open();
      store.open();
    });
    expect(existsSync(home)).toBe(false);
  });

  it('removes the tree when the body throws, and rethrows', () => {
    let home = '';
    expect(() => {
      withTempStore((store) => {
        home = store.home;
        store.open();
        throw new Error('boom');
      });
    }).toThrow('boom');
    expect(home).not.toBe('');
    expect(existsSync(home)).toBe(false);
  });

  it('tolerates a handle the body closed itself', () => {
    let home = '';
    expect(() => {
      withTempStore((store) => {
        home = store.home;
        store.open().close();
      });
    }).not.toThrow();
    expect(existsSync(home)).toBe(false);
  });

  it('opens independent handles that see one another writes', () => {
    withTempStore((store) => {
      const a = store.open();
      const b = store.open();
      expect(a).not.toBe(b);
      a.ruleProbeCache.setVerdict('shared', 'quarantined', 250);
      expect(b.ruleProbeCache.getVerdict('shared')).toEqual({
        verdict: 'quarantined',
        worstProbeMs: 250,
      });
    });
  });

  it('runs cleanups most-recent-first, while the tree still exists', () => {
    const order: string[] = [];
    let seen = false;
    let home = '';
    withTempStore((store) => {
      home = store.home;
      store.onCleanup(() => {
        order.push('first');
        seen = existsSync(store.home);
      });
      store.onCleanup(() => {
        order.push('second');
      });
    });
    expect(order).toEqual(['second', 'first']);
    expect(seen).toBe(true);
    expect(existsSync(home)).toBe(false);
  });

  it('keeps a cleanup that throws from stranding the tree', () => {
    let home = '';
    expect(() => {
      withTempStore((store) => {
        home = store.home;
        store.onCleanup(() => {
          throw new Error('cleanup failed');
        });
      });
    }).not.toThrow();
    expect(existsSync(home)).toBe(false);
  });

  it('honours a caller-supplied temp-dir prefix', () => {
    withTempStore((store) => {
      expect(basename(store.home).startsWith('aka-custom-prefix-')).toBe(true);
    }, 'aka-custom-prefix-');
  });
});

describe('createTempStore', () => {
  it('destroys once, however many times it is asked', () => {
    const store = createTempStore();
    store.open();
    store.destroy();
    expect(existsSync(store.home)).toBe(false);
    expect(() => {
      store.destroy();
    }).not.toThrow();
  });

  it('creates the data dir owner-only where modes apply', () => {
    if (process.platform === 'win32') return;
    withTempStore((store) => {
      store.open();
      expect(statSync(store.dataDir).mode & 0o777).toBe(0o700);
    });
  });
});

describe('useTempStore', () => {
  const store = useTempStore('aka-use-temp-store-');
  let firstHome = '';

  it('hands the first test an empty store', () => {
    firstHome = store.home;
    expect(store.open().ruleProbeCache.getVerdict('carried-over')).toBeUndefined();
    store.open().ruleProbeCache.setVerdict('carried-over', 'safe', 1);
  });

  it('hands the next test a different, equally empty store', () => {
    expect(store.home).not.toBe(firstHome);
    expect(existsSync(firstHome)).toBe(false);
    expect(store.open().ruleProbeCache.getVerdict('carried-over')).toBeUndefined();
  });
});
