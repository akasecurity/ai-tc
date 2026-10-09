import { describe, expect, it } from 'vitest';

import {
  MOD_POLICY_SNAPSHOT_VERSION,
  ModPolicySnapshot,
} from '../../src/zod/mod-policy-snapshot.ts';

const valid = {
  version: MOD_POLICY_SNAPSHOT_VERSION,
  generatedAt: '2026-10-09T00:00:00.000Z',
  ruleActions: { 'secrets/twilio-key': 'redact' },
  categoryActions: { secret: 'warn', pii: 'log' },
  exceptionRuleIds: ['secrets/twilio-key'],
};

describe('ModPolicySnapshot', () => {
  it('accepts a snapshot without a ruleset, which means the bundled packs', () => {
    expect(ModPolicySnapshot.safeParse(valid).success).toBe(true);
  });

  it('accepts a complete ruleset', () => {
    const rule = {
      specVersion: 1,
      id: 'acme/one',
      name: 'Acme',
      category: 'custom',
      severity: 'high',
      matcher: { type: 'keyword', keywords: ['marker'] },
    };

    expect(ModPolicySnapshot.safeParse({ ...valid, rules: [rule] }).success).toBe(true);
  });

  it.each([
    ['another version', { version: 2 }],
    ['an unknown action', { ruleActions: { 'a/b': 'shred' } }],
    ['an unknown category action', { categoryActions: { secret: 'maybe' } }],
    ['a timestamp that is not one', { generatedAt: 'yesterday' }],
    ['exception ids that are not strings', { exceptionRuleIds: [1] }],
    ['a rule that is not valid', { rules: [{ id: 'acme/one' }] }],
  ])('rejects %s', (_name, patch) => {
    expect(ModPolicySnapshot.safeParse({ ...valid, ...patch }).success).toBe(false);
  });
});
