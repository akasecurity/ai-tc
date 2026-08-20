import type { ActionTaken, DetectionCategory } from '@akasecurity/schema';
import { builtinPolicyToAction, CategoryPolicyId, KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  CATEGORY_INEXPRESSIBLE_POLICIES,
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
  it("presents the 'Set the secret detection level' prompt", () => {
    expect(presentStandingSecretPosture().prompt).toContain("Set the 'secret' detection level");
  });

  it('offers EXACTLY Redact / Warn / Block / Monitor in that order', () => {
    const { options } = presentStandingSecretPosture();
    expect(options.map((o) => o.level)).toEqual(['redact', 'warn', 'block', 'monitor']);
    expect(options.map((o) => o.label)).toEqual(['Redact', 'Warn', 'Block', 'Monitor']);
  });

  it('classifies every built-in as offered or inexpressible — no archetype falls out', () => {
    // The display order above is deliberately not the catalog's, so the palette
    // cannot be derived from it — which is exactly how an added archetype goes
    // missing here with no compile error and nothing else failing. Requiring
    // the two lists to PARTITION the canonical set forces a new one to be
    // classified rather than forgotten.
    const { options } = presentStandingSecretPosture();
    const offered = options.map((o) => o.level);
    expect([...offered, ...CATEGORY_INEXPRESSIBLE_POLICIES].sort()).toEqual(
      [...KNOWN_BUILTIN_IDS].sort(),
    );
    // Disjoint as well as covering — an id in both lists would satisfy the sort
    // above only by displacing one that is in neither.
    expect(offered.filter((id) => CATEGORY_INEXPRESSIBLE_POLICIES.includes(id))).toEqual([]);
  });

  it('the writer will not COMPILE with an archetype this axis cannot store', () => {
    // The palette excluding 'vault' is a display choice; this is the structural
    // half. writeStandingSecretPosture takes CategoryPolicyId, so a caller that
    // hands it a reversible archetype is a type error rather than a silent
    // downgrade at runtime. Asserted through the schema rather than with a
    // compiler-error directive, which would pin the compiler's wording — and
    // which cannot even be NAMED in a comment here without tsc reading it as
    // the directive itself.
    for (const id of CATEGORY_INEXPRESSIBLE_POLICIES) {
      expect(CategoryPolicyId.safeParse(id).success, `${id} must not parse`).toBe(false);
    }
    for (const id of presentStandingSecretPosture().options.map((o) => o.level)) {
      expect(CategoryPolicyId.safeParse(id).success, `${id} must parse`).toBe(true);
    }
  });

  it('does NOT offer Redact & Vault, because this axis cannot store it', () => {
    // A per-category policy row holds an ActionTaken — the verb alone — so
    // 'vault' would be written as plain 'redact' and the user would lose the
    // half they chose it for, silently. Pinned as a decision so re-adding it
    // has to come with somewhere for the reversibility to live.
    expect(presentStandingSecretPosture().options.map((o) => o.level)).not.toContain('vault');
    expect(builtinPolicyToAction('vault')).toBe('redact');
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
