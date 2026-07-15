import { describe, expect, it } from 'vitest';

import { DetectionCategory } from './finding.ts';
import { DEFAULT_ACTIONS, FULL_ENFORCEMENT_POSTURE } from './policy.ts';

describe('DEFAULT_ACTIONS — severity-floor cold-start values', () => {
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

  it('floors critical/high-severity categories to warn, low/observe-only categories to log', () => {
    expect(DEFAULT_ACTIONS.secret).toBe('warn');
    expect(DEFAULT_ACTIONS.pii).toBe('warn');
    expect(DEFAULT_ACTIONS.financial).toBe('warn');
    expect(DEFAULT_ACTIONS.phi).toBe('warn');
    expect(DEFAULT_ACTIONS.code_flaw).toBe('warn');
    expect(DEFAULT_ACTIONS.custom).toBe('warn');
    expect(DEFAULT_ACTIONS.code_context).toBe('log');
    expect(DEFAULT_ACTIONS.config).toBe('log');
  });
});

describe('FULL_ENFORCEMENT_POSTURE — the "Actively redact" onboarding preset', () => {
  it('pins the pre-severity-floor enforcement mapping', () => {
    expect(FULL_ENFORCEMENT_POSTURE).toEqual({
      secret: 'block',
      pii: 'redact',
      financial: 'redact',
      phi: 'redact',
      code_flaw: 'warn',
      custom: 'warn',
      code_context: 'warn',
      config: 'warn',
    });
  });

  it('assigns a value to every detection category', () => {
    expect(new Set(Object.keys(FULL_ENFORCEMENT_POSTURE))).toEqual(
      new Set(DetectionCategory.options),
    );
  });
});
