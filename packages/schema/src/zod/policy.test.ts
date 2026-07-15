import { describe, expect, it } from 'vitest';

import { DetectionCategory } from './finding.ts';
import { DEFAULT_ACTIONS } from './policy.ts';

describe('DEFAULT_ACTIONS — observe-first cold-start floor', () => {
  it('never hard-enforces (block) or silently rewrites payloads (redact) before onboarding', () => {
    // A fresh store with no per-category policy falls back to these. None may
    // block or redact on its own — the cold-start floor only ever surfaces
    // (warn) or logs. This guards against a category quietly regaining an
    // enforcing default and hard-acting on an un-onboarded machine.
    for (const [category, action] of Object.entries(DEFAULT_ACTIONS)) {
      expect(action, `${category} cold-start action`).not.toBe('block');
      expect(action, `${category} cold-start action`).not.toBe('redact');
    }
  });

  it('assigns a fallback action to every detection category', () => {
    expect(new Set(Object.keys(DEFAULT_ACTIONS))).toEqual(new Set(DetectionCategory.options));
  });
});
