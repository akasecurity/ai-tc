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
