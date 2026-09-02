import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

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
