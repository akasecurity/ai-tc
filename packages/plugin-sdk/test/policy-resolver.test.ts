import { randomUUID } from 'node:crypto';

import type { Policy, PolicyBundle } from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createPolicyResolver } from '../src/policy-resolver.ts';

function bundle(overrides: Partial<PolicyBundle> = {}): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
    ...overrides,
  };
}

function policy(overrides: Partial<Policy> & Pick<Policy, 'target' | 'action'>): Policy {
  return {
    id: randomUUID(),
    scope: 'global',
    enabled: true,
    ...overrides,
  };
}

describe('createPolicyResolver — actionFor', () => {
  it('prefers a ruleId-targeted policy over a category-targeted one', () => {
    const resolver = createPolicyResolver(
      bundle({
        policies: [
          policy({ target: { category: 'secret' }, action: 'block' }),
          policy({ target: { ruleId: 'pack/rule' }, action: 'log' }),
        ],
      }),
    );
    // The per-detection assignment is the more specific axis: a detection set
    // to Monitor stops enforcing even under a blocking category floor.
    expect(resolver.actionFor('pack/rule', 'secret')).toBe('log');
    // A different rule in the same category still takes the floor.
    expect(resolver.actionFor('pack/other', 'secret')).toBe('block');
  });

  it('skips a disabled policy entirely, on either axis', () => {
    const resolver = createPolicyResolver(
      bundle({
        policies: [
          policy({ target: { ruleId: 'pack/rule' }, action: 'block', enabled: false }),
          policy({ target: { category: 'secret' }, action: 'redact', enabled: false }),
        ],
      }),
    );
    // Neither row applies, so this falls all the way to the category default.
    expect(resolver.actionFor('pack/rule', 'secret')).toBe(DEFAULT_ACTIONS.secret);
  });

  it('is first-write-wins per key on both axes', () => {
    const resolver = createPolicyResolver(
      bundle({
        policies: [
          policy({ target: { ruleId: 'pack/rule' }, action: 'log' }),
          policy({ target: { ruleId: 'pack/rule' }, action: 'block' }),
          policy({ target: { category: 'pii' }, action: 'warn' }),
          policy({ target: { category: 'pii' }, action: 'block' }),
        ],
      }),
    );
    // The earliest matching row wins, which is what an explicit ruleId policy
    // preceding the pack-derived expansion relies on.
    expect(resolver.actionFor('pack/rule', 'pii')).toBe('log');
    expect(resolver.actionFor('pack/unpoliced', 'pii')).toBe('warn');
  });

  it('falls back to the per-category default, then to log for an unknown category', () => {
    const resolver = createPolicyResolver(bundle());
    expect(resolver.actionFor('pack/rule', 'secret')).toBe(DEFAULT_ACTIONS.secret);
    expect(resolver.actionFor('pack/rule', 'config')).toBe(DEFAULT_ACTIONS.config);
    // A category the taxonomy does not carry can still arrive from a stored
    // row; it resolves to the weakest enforcing action rather than throwing.
    expect(resolver.actionFor('pack/rule', 'not-a-category')).toBe('log');
  });
});

describe('createPolicyResolver — isReversible', () => {
  it('reads bundle.reversibleRuleIds and treats an absent field as none', () => {
    const withIds = createPolicyResolver(bundle({ reversibleRuleIds: ['pack/kept'] }));
    expect(withIds.isReversible('pack/kept')).toBe(true);
    expect(withIds.isReversible('pack/other')).toBe(false);

    // An older producer omits the field. Defaulting to "nothing is kept" is the
    // safe direction: no value is retained on the strength of a missing field.
    expect(createPolicyResolver(bundle()).isReversible('pack/kept')).toBe(false);
  });

  it('says nothing about whether the action strips at all', () => {
    // Reversibility is a second axis over the same action, so a monitored rule
    // can sit in the list; it is the CALLER that must require both.
    const resolver = createPolicyResolver(
      bundle({
        policies: [policy({ target: { ruleId: 'pack/monitored' }, action: 'log' })],
        reversibleRuleIds: ['pack/monitored'],
      }),
    );
    expect(resolver.actionFor('pack/monitored', 'secret')).toBe('log');
    expect(resolver.isReversible('pack/monitored')).toBe(true);
  });
});

describe('createPolicyResolver — never throws', () => {
  it('survives a bundle whose policies cannot be indexed and resolves through the defaults', () => {
    // A bundle from an unsigned on-disk cache can be anything. Building the
    // index must not throw on the hook path, and a bundle it cannot read must
    // yield NO policies rather than the half it managed to index — half an
    // index is a policy set nobody authored.
    const broken = bundle({
      policies: [
        policy({ target: { ruleId: 'pack/rule' }, action: 'block' }),
        {
          enabled: true,
          get target(): never {
            throw new Error('unreadable row');
          },
        } as unknown as Policy,
      ],
    });
    const resolver = createPolicyResolver(broken);
    expect(resolver.actionFor('pack/rule', 'secret')).toBe(DEFAULT_ACTIONS.secret);
    expect(resolver.isReversible('pack/rule')).toBe(false);
  });

  it('survives a bundle with no policies array at all', () => {
    const resolver = createPolicyResolver({ version: 'x' } as unknown as PolicyBundle);
    expect(resolver.actionFor('pack/rule', 'secret')).toBe(DEFAULT_ACTIONS.secret);
    expect(resolver.actionFor('pack/rule', 'nope')).toBe('log');
    expect(resolver.isReversible('pack/rule')).toBe(false);
  });
});
