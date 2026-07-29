import { describe, expect, it } from 'vitest';

import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-rule-probe-');

describe('SqliteRuleProbeCacheRepository (via LocalDatabase.ruleProbeCache)', () => {
  it('returns undefined for an unseen rule key', () => {
    expect(store.open().ruleProbeCache.getVerdict('unseen')).toBeUndefined();
  });

  it('round-trips a safe verdict', () => {
    const db = store.open();
    db.ruleProbeCache.setVerdict('rule-a', 'safe', 1.8);
    expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.8 });
  });

  it('round-trips a quarantined verdict', () => {
    const db = store.open();
    db.ruleProbeCache.setVerdict('rule-b', 'quarantined', 250);
    expect(db.ruleProbeCache.getVerdict('rule-b')).toEqual({
      verdict: 'quarantined',
      worstProbeMs: 250,
    });
  });

  it('upserts on rule_key: a re-check overwrites the verdict', () => {
    const db = store.open();
    db.ruleProbeCache.setVerdict('rule-a', 'quarantined', 500);
    db.ruleProbeCache.setVerdict('rule-a', 'safe', 2.1);
    expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 2.1 });
  });

  it('persists across reopen', () => {
    const db1 = store.open();
    db1.ruleProbeCache.setVerdict('rule-a', 'safe', 1.2);
    db1.close();

    const db2 = store.open();
    expect(db2.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.2 });
  });
});

// A quarantine verdict is reached by the machine on its own, from a wall-clock
// measurement, and it excludes the rule from every later scan forever. That
// makes an undo part of the contract, not a convenience — and it has to leave
// the measurements worth keeping alone.
describe('clearing quarantine verdicts', () => {
  it('counts only the quarantined rules', () => {
    const db = store.open();
    db.ruleProbeCache.setVerdict('safe-a', 'safe', 1);
    db.ruleProbeCache.setVerdict('safe-b', 'safe', 2);
    db.ruleProbeCache.setVerdict('bad-a', 'quarantined', 900);

    expect(db.ruleProbeCache.countQuarantined()).toBe(1);
  });

  it('forgets the quarantines, keeps the safe verdicts, and reports how many went', () => {
    const db = store.open();
    db.ruleProbeCache.setVerdict('safe-a', 'safe', 1);
    db.ruleProbeCache.setVerdict('bad-a', 'quarantined', 900);
    db.ruleProbeCache.setVerdict('bad-b', 'quarantined', 1_200);

    expect(db.ruleProbeCache.clearQuarantined()).toBe(2);
    expect(db.ruleProbeCache.countQuarantined()).toBe(0);
    // The rules come back only because their verdict is GONE, not overwritten:
    // an unseen key is what makes the next load measure them again.
    expect(db.ruleProbeCache.getVerdict('bad-a')).toBeUndefined();
    // A 'safe' verdict is a real measurement worth keeping — dropping it would
    // make every rule on the machine pay the battery again for nothing.
    expect(db.ruleProbeCache.getVerdict('safe-a')).toEqual({ verdict: 'safe', worstProbeMs: 1 });
  });

  it('is a no-op on a store with nothing quarantined', () => {
    const db = store.open();
    db.ruleProbeCache.setVerdict('safe-a', 'safe', 1);

    expect(db.ruleProbeCache.clearQuarantined()).toBe(0);
    expect(db.ruleProbeCache.getVerdict('safe-a')).toBeDefined();
  });

  it('survives a reopen — the verdicts are really gone, not just uncached', () => {
    const db1 = store.open();
    db1.ruleProbeCache.setVerdict('bad-a', 'quarantined', 900);
    db1.ruleProbeCache.clearQuarantined();
    db1.close();

    const db2 = store.open();
    expect(db2.ruleProbeCache.getVerdict('bad-a')).toBeUndefined();
  });
});
