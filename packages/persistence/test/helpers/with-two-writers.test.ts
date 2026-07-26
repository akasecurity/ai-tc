import { existsSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { withTwoWriters, withWriters } from './with-two-writers.ts';

// Two live handles on one file is the shape the product runs in and the shape
// no store test could take before these helpers existed.

describe('withTwoWriters', () => {
  it('yields two distinct handles on one store', () => {
    withTwoWriters((a, b, store) => {
      expect(a).not.toBe(b);
      expect(existsSync(store.dbFile)).toBe(true);
    });
  });

  it('lets each handle read what the other committed', () => {
    withTwoWriters((a, b) => {
      a.ruleProbeCache.setVerdict('from-a', 'safe', 1.1);
      b.ruleProbeCache.setVerdict('from-b', 'quarantined', 300);

      expect(b.ruleProbeCache.getVerdict('from-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.1 });
      expect(a.ruleProbeCache.getVerdict('from-b')).toEqual({
        verdict: 'quarantined',
        worstProbeMs: 300,
      });
    });
  });

  it('loses nothing when writes alternate between the handles', () => {
    withTwoWriters((a, b) => {
      for (let i = 0; i < 50; i += 1) {
        (i % 2 === 0 ? a : b).ruleProbeCache.setVerdict(`rule-${String(i)}`, 'safe', i);
      }
      for (let i = 0; i < 50; i += 1) {
        expect(a.ruleProbeCache.getVerdict(`rule-${String(i)}`)).toEqual({
          verdict: 'safe',
          worstProbeMs: i,
        });
      }
    });
  });

  it('closes both handles and removes the tree afterwards', () => {
    let home = '';
    withTwoWriters((_a, _b, store) => {
      home = store.home;
    });
    expect(existsSync(home)).toBe(false);
  });
});

describe('withWriters', () => {
  it('opens the requested number of handles, all on one store', () => {
    withWriters(5, (writers, store) => {
      expect(writers).toHaveLength(5);
      expect(new Set(writers).size).toBe(5);

      writers.forEach((db, i) => {
        db.ruleProbeCache.setVerdict(`writer-${String(i)}`, 'safe', i);
      });
      // Every writer's row is visible from a further, independent handle: one
      // file underneath, not five.
      const reader = store.open();
      writers.forEach((_db, i) => {
        expect(reader.ruleProbeCache.getVerdict(`writer-${String(i)}`)).toEqual({
          verdict: 'safe',
          worstProbeMs: i,
        });
      });
      expect(existsSync(store.dbFile)).toBe(true);
    });
  });

  it('rejects a count that cannot describe a set of handles', () => {
    for (const count of [0, -1, 1.5]) {
      expect(() => {
        withWriters(count, () => undefined);
      }).toThrow(/positive integer/);
    }
  });

  it('removes the tree when the body throws', () => {
    let home = '';
    expect(() => {
      withWriters(3, (_writers, store) => {
        home = store.home;
        throw new Error('boom');
      });
    }).toThrow('boom');
    expect(existsSync(home)).toBe(false);
  });

  it('holds the writers open until an async body finishes', async () => {
    let home = '';
    await withWriters(3, async (writers, store) => {
      home = store.home;
      await Promise.resolve();
      // Every handle is still live after the await, not closed out from under
      // the body by an eager teardown.
      writers.forEach((db, i) => {
        db.ruleProbeCache.setVerdict(`async-${String(i)}`, 'safe', i);
      });
      writers.forEach((_db, i) => {
        expect(writers[0]?.ruleProbeCache.getVerdict(`async-${String(i)}`)).toEqual({
          verdict: 'safe',
          worstProbeMs: i,
        });
      });
    });
    expect(existsSync(home)).toBe(false);
  });
});
