import { describe, expect, it } from 'vitest';

import {
  MaskedSecretFinding,
  RemediationEntryContext,
  RemediationOption,
  RotationChecklistEntry,
} from '../../src/zod/index.ts';

// A raw-free per-finding summary: provider, a masked-only token (never the raw
// key), the transcript artifact it was found in, and its still-valid state.
const maskedFinding = {
  provider: 'stripe',
  maskedToken: 'sk_live_…4f2c',
  where: { filePath: '~/.claude/projects/acme/transcript.jsonl', span: { start: 120, end: 148 } },
  state: 'still-valid',
};

describe('MaskedSecretFinding', () => {
  it('parses a masked per-finding summary', () => {
    expect(MaskedSecretFinding.safeParse(maskedFinding).success).toBe(true);
  });

  it('parses a summary whose location carries only a filePath (span optional)', () => {
    const { span, ...whereWithoutSpan } = maskedFinding.where;
    void span;
    expect(
      MaskedSecretFinding.safeParse({ ...maskedFinding, where: whereWithoutSpan }).success,
    ).toBe(true);
  });

  it('rejects a shape carrying a raw-looking secret field name', () => {
    expect(
      MaskedSecretFinding.safeParse({
        ...maskedFinding,
        rawToken: 'sk_live_EXAMPLE0000000000000000',
      }).success,
    ).toBe(false);
  });

  it('rejects an unknown state value', () => {
    expect(MaskedSecretFinding.safeParse({ ...maskedFinding, state: 'expired' }).success).toBe(
      false,
    );
  });

  it('rejects a location missing its filePath', () => {
    expect(
      MaskedSecretFinding.safeParse({ ...maskedFinding, where: { span: { start: 0, end: 1 } } })
        .success,
    ).toBe(false);
  });

  it('parses summaries with and without an observed-at exposure signal', () => {
    expect(MaskedSecretFinding.safeParse(maskedFinding).success).toBe(true);
    expect(
      MaskedSecretFinding.safeParse({ ...maskedFinding, observedAt: '2026-07-19T12:30:00Z' })
        .success,
    ).toBe(true);
  });
});

describe('RotationChecklistEntry', () => {
  const checklistEntry = {
    provider: 'stripe',
    maskedToken: 'sk_live_…4f2c',
    consolePath: 'dashboard.stripe.com → Developers → API keys',
    occurrenceSpread: 3,
  };

  it('parses a masked checklist entry', () => {
    expect(RotationChecklistEntry.safeParse(checklistEntry).success).toBe(true);
  });

  it('rejects an entry carrying an unmodeled raw field', () => {
    expect(
      RotationChecklistEntry.safeParse({
        ...checklistEntry,
        rawToken: 'sk_live_EXAMPLE0000000000000000',
      }).success,
    ).toBe(false);
  });

  it.each([0, -1])('rejects occurrenceSpread %i', (occurrenceSpread) => {
    expect(RotationChecklistEntry.safeParse({ ...checklistEntry, occurrenceSpread }).success).toBe(
      false,
    );
  });
});

describe('RemediationOption', () => {
  it('accepts exactly the four remediation decision ids', () => {
    for (const id of ['redact-rotation-checklist', 'redact-only', 'set-secret-redact', 'leave']) {
      expect(RemediationOption.safeParse(id).success).toBe(true);
    }
  });

  it('rejects a fifth id', () => {
    expect(RemediationOption.safeParse('rotate-now').success).toBe(false);
  });
});

describe('RemediationEntryContext', () => {
  it('parses with only an entry-source tag and no wizard state', () => {
    expect(RemediationEntryContext.safeParse({ entrySource: 'first-run' }).success).toBe(true);
    expect(RemediationEntryContext.safeParse({ entrySource: 'pre-push' }).success).toBe(true);
    expect(RemediationEntryContext.safeParse({ entrySource: 'secret-scan' }).success).toBe(true);
  });

  it('rejects an unknown entry source', () => {
    expect(RemediationEntryContext.safeParse({ entrySource: 'onboarding' }).success).toBe(false);
  });

  it('rejects a context carrying wizard state', () => {
    expect(
      RemediationEntryContext.safeParse({ entrySource: 'first-run', wizardFrame: '0.6' }).success,
    ).toBe(false);
  });
});
