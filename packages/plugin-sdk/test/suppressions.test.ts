import { describe, expect, it, vi } from 'vitest';

import type { ExceptionWriter } from '../src/suppressions.ts';
import { applySetupTriageSuppressions, THIRTY_DAYS_MS } from '../src/suppressions.ts';

type CreateArg = Parameters<ExceptionWriter['create']>[0];

const entry = {
  ruleId: 'core-secret/aws',
  category: 'secret' as const,
  valueFingerprint: 'ab'.repeat(32),
  keyVersion: 1,
  maskedValue: 'A***Z',
  justification: 'placeholder key in a fixture',
};

describe('applySetupTriageSuppressions', () => {
  it('writes a temporary 30-day setup-triage grant per entry', async () => {
    const create = vi.fn<(input: CreateArg) => Promise<unknown>>().mockResolvedValue({});
    const now = 1_700_000_000_000;
    const res = await applySetupTriageSuppressions([entry], { create }, { createdBy: 'me', now });
    expect(res.written).toBe(1);
    const call = create.mock.calls[0];
    if (!call) throw new Error('expected create() to have been called');
    const arg = call[0];
    expect(arg.createdVia).toBe('setup-triage');
    expect(arg.scope).toBe('temporary');
    expect(arg.maxUses).toBeNull();
    expect(arg.createdBy).toBe('me');
    // expiresAt is 30 days out, encoded as an ISO string (the repo converts via isoToEpochMillis).
    expect(new Date(arg.expiresAt).getTime()).toBe(now + THIRTY_DAYS_MS);
  });

  it('is idempotent: a duplicate-active-exception is caught, batch continues', async () => {
    const dupErr = Object.assign(new Error('dup'), { code: 'duplicate-active-exception' });
    const create = vi
      .fn()
      .mockRejectedValueOnce(dupErr) // first entry already suppressed
      .mockResolvedValueOnce({}); // second writes
    const res = await applySetupTriageSuppressions(
      [entry, { ...entry, valueFingerprint: 'cd'.repeat(32) }],
      { create },
      { createdBy: 'me', now: 1 },
    );
    expect(res.written).toBe(1);
    expect(res.skippedDuplicate).toBe(1);
  });

  it('rethrows a non-duplicate error (fail loud on a real fault)', async () => {
    const create = vi.fn().mockRejectedValue(new Error('disk full'));
    await expect(
      applySetupTriageSuppressions([entry], { create }, { createdBy: 'me', now: 1 }),
    ).rejects.toThrow('disk full');
  });
});
