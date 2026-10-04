import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { builtinPolicyToAction, severityFloorPosture } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { applyCategoryPosture, detectPostureChanges } from '../src/posture.ts';

function fakeWriter(initial: Partial<Record<DetectionCategory, ActionTaken>> = {}) {
  const store = new Map<DetectionCategory, ActionTaken>(
    Object.entries(initial) as [DetectionCategory, ActionTaken][],
  );
  return {
    store,
    getCategoryAction: vi.fn((category: DetectionCategory) => store.get(category)),
    upsertCategoryAction: vi.fn((category: DetectionCategory, action: ActionTaken) => {
      store.set(category, action);
    }),
  };
}

describe('applyCategoryPosture', () => {
  it('fill-gaps (default): never overwrites a category that already has a policy row', () => {
    const writer = fakeWriter({ secret: 'block' });
    applyCategoryPosture({ secret: 'warn', pii: 'warn' }, writer);
    expect(writer.store.get('secret')).toBe('block');
    expect(writer.store.get('pii')).toBe('warn');
  });

  it('fill-gaps: fills a row the writer reports as an untouched seed, keeps a chosen one', () => {
    const writer = {
      ...fakeWriter({ secret: 'log', pii: 'log' }),
      isCategoryChosen: (category: DetectionCategory) => category === 'pii',
    };
    applyCategoryPosture({ secret: 'warn', pii: 'warn' }, writer);
    expect(writer.store.get('secret')).toBe('warn');
    expect(writer.store.get('pii')).toBe('log');
  });

  it('overwrite: replaces an existing category row', () => {
    const writer = fakeWriter({ secret: 'block' });
    applyCategoryPosture({ secret: 'warn' }, writer, 'overwrite');
    expect(writer.store.get('secret')).toBe('warn');
  });

  it('skips a category whose value is undefined, even though the static type disallows it', () => {
    const writer = fakeWriter();
    // A present key with an undefined value.
    const posture = { secret: undefined } as unknown as Partial<
      Record<DetectionCategory, BuiltinPolicyId>
    >;
    applyCategoryPosture(posture, writer, 'overwrite');
    expect(writer.upsertCategoryAction).not.toHaveBeenCalled();
  });
});

// The same calls against a real store, so the seed-versus-choice reading the
// repository gives is what is under test, not a fake's. The floor is chosen to
// differ from the Monitor seed for at least one category; otherwise writing it
// and skipping it would end on the same rows and the test could not tell.
describe('applyCategoryPosture against the real policies repository', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-posture-'));
  });
  afterEach(() => {
    removeTree(dir);
  });

  const floor = severityFloorPosture();
  const raised = (Object.keys(floor) as DetectionCategory[]).filter(
    (c) => builtinPolicyToAction(floor[c]) !== 'log',
  );

  it('a fresh install ends on the floor, not on the Monitor seed', () => {
    expect(raised.length).toBeGreaterThan(0);
    const db = openLocalDatabase(dir);
    try {
      for (const c of raised) expect(db.policies.getCategoryAction(c)).toBe('log');
      applyCategoryPosture(floor, db.policies);
      for (const c of raised) {
        expect(db.policies.getCategoryAction(c)).toBe(builtinPolicyToAction(floor[c]));
      }
    } finally {
      db.close();
    }
  });

  it('fill-gaps leaves a category somebody chose, even when it chose Monitor', () => {
    const [category] = raised;
    if (category === undefined) throw new Error('no category above Monitor in the floor');
    const db = openLocalDatabase(dir);
    try {
      db.policies.upsertCategoryAction(category, 'log');
      applyCategoryPosture(floor, db.policies);
      expect(db.policies.getCategoryAction(category)).toBe('log');
    } finally {
      db.close();
    }
  });
});

describe('detectPostureChanges', () => {
  it('flags a downgrade (existing action stronger than the proposed one)', () => {
    const changes = detectPostureChanges(
      { secret: 'warn' },
      { secret: { action: 'block', enabled: true } },
    );
    expect(changes).toEqual([{ category: 'secret', from: 'block', to: 'warn', kind: 'downgrade' }]);
  });

  it('flags a re-enable (same-or-stronger action, but the row is currently disabled)', () => {
    const changes = detectPostureChanges(
      { secret: 'block' },
      { secret: { action: 'block', enabled: false } },
    );
    expect(changes).toEqual([
      { category: 'secret', from: 'block', to: 'block', kind: 're-enable' },
    ]);
  });

  it('reports nothing for a same-strength, already-enabled category', () => {
    const changes = detectPostureChanges(
      { secret: 'block' },
      { secret: { action: 'block', enabled: true } },
    );
    expect(changes).toEqual([]);
  });

  it('reports nothing for a category with no existing row (nothing to weaken)', () => {
    const changes = detectPostureChanges({ secret: 'warn' }, {});
    expect(changes).toEqual([]);
  });

  // The stored action comes from a column with no enum constraint, so a row a
  // newer build wrote can carry an action this one cannot place on the ladder.
  // The ladder ranks that below everything — the reading the enforcement gates
  // need — but this differ warns a PERSON, and it must not answer "no change
  // here" to a comparison it was unable to make. Both directions are asserted,
  // because a rank of -1 would otherwise make the second case pass for the
  // wrong reason.
  it('flags a downgrade when the stored action is one this build cannot rank', () => {
    const stored = 'quarantine' as ActionTaken;
    const strongest: BuiltinPolicyId = 'block';
    const weakest: BuiltinPolicyId = 'monitor';
    expect(
      detectPostureChanges({ secret: strongest }, { secret: { action: stored, enabled: true } }),
    ).toEqual([{ category: 'secret', from: stored, to: 'block', kind: 'downgrade' }]);
    expect(
      detectPostureChanges({ secret: weakest }, { secret: { action: stored, enabled: true } }),
    ).toEqual([{ category: 'secret', from: stored, to: 'log', kind: 'downgrade' }]);
  });

  // The differ ranks actions through the same ladder the enforcement collapse
  // uses, so the two cannot come to disagree about which of a pair enforces
  // more. Every adjacent rung is exercised: a pair swapped either way must be
  // a downgrade in exactly one direction.
  it('ranks every adjacent rung of the ladder the same way in both directions', () => {
    const rungs: [ActionTaken, BuiltinPolicyId][] = [
      ['log', 'monitor'],
      ['warn', 'warn'],
      ['redact', 'redact'],
      ['block', 'block'],
    ];
    for (let i = 0; i < rungs.length - 1; i += 1) {
      const weaker = rungs[i];
      const stronger = rungs[i + 1];
      if (weaker === undefined || stronger === undefined) throw new Error('bad rung table');
      // stronger → weaker weakens enforcement.
      expect(
        detectPostureChanges(
          { secret: weaker[1] },
          { secret: { action: stronger[0], enabled: true } },
        ),
      ).toEqual([{ category: 'secret', from: stronger[0], to: weaker[0], kind: 'downgrade' }]);
      // weaker → stronger does not.
      expect(
        detectPostureChanges(
          { secret: stronger[1] },
          { secret: { action: weaker[0], enabled: true } },
        ),
      ).toEqual([]);
    }
  });

  it('an upgrade (proposed stronger than existing, already enabled) is not flagged', () => {
    const changes = detectPostureChanges(
      { secret: 'block' },
      { secret: { action: 'warn', enabled: true } },
    );
    expect(changes).toEqual([]);
  });
});
