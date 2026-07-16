import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { RawEgressError } from '@akasecurity/plugin-sdk';
import type { TriageHit } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import {
  deletePlanFile,
  PLAN_FILE_VERSION,
  readPlanFile,
  writePlanFile,
} from '../../src/triage/plan-file.ts';
import { planTriageWriteback, type TriageWritebackPlan } from '../../src/triage/writeback.ts';

const RAW = 'AKIAIOSFODNN7EXAMPLE';
const FP = 'ab'.repeat(32);

const hit = (over: Partial<TriageHit> = {}): TriageHit => ({
  ruleId: 'core-secret/aws',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***E',
  rawMatch: RAW,
  context: `export KEY=${RAW} # prod`,
  confidence: 0.9,
  id: '0',
  valueFingerprint: FP,
  keyVersion: 1,
  ...over,
});

const rec = (notes = 'looks routine') => ({
  perCategory: [
    {
      category: 'secret' as const,
      action: 'warn' as const,
      reasoning: 'canonical fake AWS example key',
      genuineCount: 0,
      fpCount: 1,
      fpIds: ['0'],
    },
  ],
  notes,
});

const cleanup: string[] = [];
afterEach(() => {
  for (const p of cleanup.splice(0)) rmSync(join(p, '..'), { recursive: true, force: true });
});

describe('plan-file round-trip', () => {
  it('persists a plan and reads back exactly its posture, entries, and notes', () => {
    const plan = planTriageWriteback([hit()], rec());
    const current = { secret: 'block' as const };
    const path = writePlanFile(plan, current, [RAW]);
    cleanup.push(path);

    const back = readPlanFile(path);
    expect(back.version).toBe(PLAN_FILE_VERSION);
    expect(back.posture).toEqual(plan.posture);
    expect(back.entries).toEqual(plan.entries);
    expect(back.notes).toBe(plan.notes);
    expect(back.current).toEqual(current);
    // the join survives too, so the confirm step could re-render the gate
    expect(back.join).toEqual(plan.join);
    // the showcase round-trips (raw-free: reasoning + counts + enums)
    expect(back.showcase).toEqual(plan.showcase);
    expect(back.showcase).toHaveLength(1);
    expect(back.showcase[0]).toMatchObject({ category: 'secret', action: 'warn' });
  });
});

describe('plan-file raw safety', () => {
  it('the persisted file contains no raw detected value', () => {
    const plan = planTriageWriteback([hit()], rec());
    const path = writePlanFile(plan, {}, [RAW]);
    cleanup.push(path);

    const text = readFileSync(path, 'utf8');
    expect(text).not.toContain(RAW);
    // sanity: it DID persist the masked evidence, so we know the file isn't empty
    expect(text).toContain('core-secret/aws');
  });

  it('fails LOUD (backstop) if a raw value ever survives into the plan document', () => {
    // Craft a poisoned plan whose justification smuggles the raw value, and assert
    // writePlanFile refuses to persist it rather than leaking a secret to disk.
    const poisoned: TriageWritebackPlan = {
      entries: [
        {
          ruleId: 'core-secret/aws',
          category: 'secret',
          valueFingerprint: FP,
          keyVersion: 1,
          maskedValue: 'A***E',
          justification: `totally fine ${RAW} trust me`,
        },
      ],
      posture: { secret: 'warn' },
      showcase: [],
      join: [],
      notes: '',
      skipped: [],
    };
    expect(() => writePlanFile(poisoned, {}, [RAW])).toThrow(RawEgressError);
  });
});

describe('readPlanFile fails loud on a bad file', () => {
  it('throws on a missing file', () => {
    expect(() => readPlanFile(join(tmpdir(), 'aka-does-not-exist-xyz', 'plan.json'))).toThrow();
  });

  it('throws on malformed JSON', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-plan-bad-'));
    const path = join(dir, 'plan.json');
    writeFileSync(path, '{ not json ');
    cleanup.push(path);
    expect(() => readPlanFile(path)).toThrow();
  });

  it('throws on a wrong-version / schema-invalid document', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-plan-ver-'));
    const path = join(dir, 'plan.json');
    writeFileSync(path, JSON.stringify({ version: 999, token: 'x' }));
    cleanup.push(path);
    expect(() => readPlanFile(path)).toThrow();
  });
});

describe('deletePlanFile', () => {
  it('removes the file and is idempotent on an already-gone path', () => {
    const plan = planTriageWriteback([hit()], rec());
    const path = writePlanFile(plan, {}, [RAW]);
    cleanup.push(path);
    deletePlanFile(path);
    expect(() => readPlanFile(path)).toThrow();
    expect(() => {
      deletePlanFile(path);
    }).not.toThrow();
  });

  it('removes a preview-minted plan AND its now-empty dedicated temp dir', () => {
    const plan = planTriageWriteback([hit()], rec());
    const path = writePlanFile(plan, {}, [RAW]);
    cleanup.push(path);
    deletePlanFile(path);
    // the dedicated mkdtemp dir writePlanFile minted held only this file, so it
    // is gone too — no lingering empty directory behind
    expect(existsSync(dirname(path))).toBe(false);
  });

  it('NEVER deletes siblings when --plan points at a shared directory', () => {
    // The confirm path takes --plan <path> from user argv. If a valid plan lives
    // in a directory holding OTHER files, deletePlanFile must remove only the plan
    // file — the old `rmSync(dirname, { recursive })` would have wiped the lot.
    const dir = mkdtempSync(join(tmpdir(), 'aka-shared-'));
    cleanup.push(join(dir, 'x'));
    const planPath = join(dir, 'setup-plan.json');
    const plan = planTriageWriteback([hit()], rec());
    writeFileSync(planPath, JSON.stringify(readPlanFileDoc(plan)));
    const sibling = join(dir, 'precious.txt');
    writeFileSync(sibling, 'do not delete me');

    deletePlanFile(planPath);

    expect(existsSync(planPath)).toBe(false);
    expect(existsSync(sibling)).toBe(true);
    expect(existsSync(dir)).toBe(true);
  });
});

// Serialize a plan the way writePlanFile would, for the shared-dir test (which
// must place the file itself rather than let writePlanFile mint a temp dir).
function readPlanFileDoc(plan: TriageWritebackPlan) {
  return {
    version: PLAN_FILE_VERSION,
    posture: plan.posture,
    entries: plan.entries,
    showcase: plan.showcase,
    join: plan.join,
    notes: plan.notes,
    current: {},
  };
}
