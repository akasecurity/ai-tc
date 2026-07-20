import type { ActionTaken, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  presentStandingSecretPosture,
  writeStandingSecretPosture,
} from '../../src/remediation/posture.ts';
import type { CategoryPolicyWriter } from '../../src/triage/writeback.ts';

// A fake policies writer capturing every category action write, so the test
// asserts the standing-posture write hits the policies store (the enforcement
// store detections read) and never a settings.json surface — the writer only
// ever takes this CategoryPolicyWriter slice, so a settings write is not reachable.
function fakePolicies(): CategoryPolicyWriter & {
  readonly writes: [DetectionCategory, ActionTaken][];
} {
  const posture: Partial<Record<DetectionCategory, ActionTaken>> = {};
  const writes: [DetectionCategory, ActionTaken][] = [];
  return {
    writes,
    getCategoryAction: (c) => posture[c],
    upsertCategoryAction: (c, a) => {
      posture[c] = a;
      writes.push([c, a]);
    },
  };
}

// A policies writer whose write throws — the injected store-write failure the
// standing-posture fail-open path must catch without breaking the session.
function throwingPolicies(): CategoryPolicyWriter {
  return {
    getCategoryAction: () => undefined,
    upsertCategoryAction: () => {
      throw new Error('policies store write failed');
    },
  };
}

describe('presentStandingSecretPosture — standing-posture palette', () => {
  it("presents the 'Set the secret posture' prompt", () => {
    expect(presentStandingSecretPosture().prompt).toContain("Set the 'secret' posture");
  });

  it('offers EXACTLY Redact / Warn / Block / Monitor in that order', () => {
    const { options } = presentStandingSecretPosture();
    expect(options.map((o) => o.level)).toEqual(['redact', 'warn', 'block', 'monitor']);
    expect(options.map((o) => o.label)).toEqual(['Redact', 'Warn', 'Block', 'Monitor']);
  });
});

describe('writeStandingSecretPosture — standing posture write', () => {
  it('persists the chosen palette level for the secret category to the policies store', () => {
    const policies = fakePolicies();
    const result = writeStandingSecretPosture('block', policies);

    expect(result).toEqual({ persisted: true, level: 'block' });
    // The chosen palette level lands on the secret category as its enforcement
    // action (block → block), written via applyCategoryPosture in overwrite mode.
    expect(policies.getCategoryAction('secret')).toBe('block');
    // Only the secret category is touched — no collateral posture write.
    expect(policies.writes).toEqual([['secret', 'block']]);
  });

  it('overwrites an existing secret posture (explicit standing choice, not fill-gaps)', () => {
    const policies = fakePolicies();
    policies.upsertCategoryAction('secret', 'warn');
    writeStandingSecretPosture('block', policies);
    expect(policies.getCategoryAction('secret')).toBe('block');
  });

  it('persists secret → redact for the "Set \'secret\' to redact" shortcut', () => {
    const policies = fakePolicies();
    const result = writeStandingSecretPosture('redact', policies);

    expect(result).toEqual({ persisted: true, level: 'redact' });
    expect(policies.getCategoryAction('secret')).toBe('redact');
    // No redaction and no deliverable: the standing-posture writer writes posture
    // and nothing else — it never touches an artifact or a rotation checklist, so
    // the only observed effect is the single secret-category policies write.
    expect(policies.writes).toEqual([['secret', 'redact']]);
  });
});

describe('writeStandingSecretPosture — fail-open on write failure', () => {
  it('catches an applyCategoryPosture write throw and does not propagate it', () => {
    expect(() => writeStandingSecretPosture('redact', throwingPolicies())).not.toThrow();
  });

  it('claims NO false success when the write failed', () => {
    const result = writeStandingSecretPosture('redact', throwingPolicies());
    // The failure is reported honestly — the caller cannot read a persisted level
    // off a failed write, so the posture is never reported as persisted.
    expect(result.persisted).toBe(false);
    expect(result).not.toHaveProperty('level');
  });
});
