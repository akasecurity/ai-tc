import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import { applyCategoryPosture, detectPostureChanges } from './posture.ts';

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

  it('an upgrade (proposed stronger than existing, already enabled) is not flagged', () => {
    const changes = detectPostureChanges(
      { secret: 'block' },
      { secret: { action: 'warn', enabled: true } },
    );
    expect(changes).toEqual([]);
  });
});
