import { describe, expect, it } from 'vitest';

import { ModFinding } from '../../src/zod/mod-finding.ts';

const valid = {
  v: 1,
  id: 'a1b2c3d4e5f60718',
  at: '2026-10-13T12:00:00.000Z',
  ruleId: 'secrets/github-pat',
  shortName: 'GitHub token',
  category: 'secret',
  severity: 'critical',
  action: 'vaulted',
  where: 'prompt',
  pointer: '[[aka:secret:AE.AAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA]]',
};

describe('ModFinding', () => {
  it('accepts a vaulted finding', () => {
    expect(ModFinding.safeParse(valid).success).toBe(true);
  });
  it('accepts a finding with no pointer and no short name', () => {
    const bare: Record<string, unknown> = { ...valid, action: 'blocked' };
    delete bare.pointer;
    delete bare.shortName;
    expect(ModFinding.safeParse(bare).success).toBe(true);
  });
  it('refuses a record carrying a raw value or span', () => {
    const raw = ModFinding.safeParse({ ...valid, rawMatch: 'ghp_x' });
    expect(raw.success).toBe(false);
    expect(raw.error?.issues[0]?.code).toBe('unrecognized_keys');
    expect(ModFinding.safeParse({ ...valid, span: { start: 0, end: 4 } }).success).toBe(false);
  });
  it('refuses a vaulted finding with no pointer', () => {
    const bare: Record<string, unknown> = { ...valid };
    delete bare.pointer;
    expect(ModFinding.safeParse(bare).success).toBe(false);
  });
  it('refuses a pointer on a finding that was not vaulted', () => {
    expect(ModFinding.safeParse({ ...valid, action: 'blocked' }).success).toBe(false);
  });
  it('registers its schema id after the refinement', () => {
    expect(ModFinding.meta()?.id).toBe('ModFinding');
  });
  it('refuses a pointer that is not a vault pointer', () => {
    expect(ModFinding.safeParse({ ...valid, pointer: 'ghp_realvalue' }).success).toBe(false);
  });
});
