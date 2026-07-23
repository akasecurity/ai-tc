import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-rule-probe-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('SqliteRuleProbeCacheRepository (via LocalDatabase.ruleProbeCache)', () => {
  it('returns undefined for an unseen rule key', () => {
    const db = openLocalDatabase(dir);
    expect(db.ruleProbeCache.getVerdict('unseen')).toBeUndefined();
    db.close();
  });

  it('round-trips a safe verdict', () => {
    const db = openLocalDatabase(dir);
    db.ruleProbeCache.setVerdict('rule-a', 'safe', 1.8);
    expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.8 });
    db.close();
  });

  it('round-trips a quarantined verdict', () => {
    const db = openLocalDatabase(dir);
    db.ruleProbeCache.setVerdict('rule-b', 'quarantined', 250);
    expect(db.ruleProbeCache.getVerdict('rule-b')).toEqual({
      verdict: 'quarantined',
      worstProbeMs: 250,
    });
    db.close();
  });

  it('upserts on rule_key: a re-check overwrites the verdict', () => {
    const db = openLocalDatabase(dir);
    db.ruleProbeCache.setVerdict('rule-a', 'quarantined', 500);
    db.ruleProbeCache.setVerdict('rule-a', 'safe', 2.1);
    expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 2.1 });
    db.close();
  });

  it('persists across reopen', () => {
    const db1 = openLocalDatabase(dir);
    db1.ruleProbeCache.setVerdict('rule-a', 'safe', 1.2);
    db1.close();

    const db2 = openLocalDatabase(dir);
    expect(db2.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.2 });
    db2.close();
  });
});
