import { describe, expect, it } from 'vitest';

import {
  controlPlaneName,
  defaultWorkspaceSettings,
  isAttached,
  isModelJudgeConsentValid,
  MODEL_JUDGE_PAYLOAD_VERSION,
  toEventRow,
  toFindingRow,
  WORKSPACE_SETTINGS_SPEC_VERSION,
  WorkspaceSettings,
} from '../../src/zod/local.ts';

const EVENT = '00000000-0000-0000-0000-0000000000d4';
const FINDING = '00000000-0000-0000-0000-0000000000e5';
const ISO = '2026-06-18T00:00:00.000Z';

describe('WorkspaceSettings (versioned, default-filled)', () => {
  it('fills defaults for an empty object so older/missing files stay valid', () => {
    const s = WorkspaceSettings.parse({});
    expect(s).toMatchObject({
      specVersion: WORKSPACE_SETTINGS_SPEC_VERSION,
      runMode: 'standalone',
      policy: 'redact',
      // Historical scanning is opt-in — defaults to session-only, never an
      // assumed grant for a settings.json written before the field existed.
      historicalAccess: 'session-only',
    });
    // onboardedAt is absent until /aka:setup completes — that absence is "not onboarded"
    expect(s.onboardedAt).toBeUndefined();
  });

  it('enables in-place Data Shares extraction by default', () => {
    expect(WorkspaceSettings.parse({}).dataSharesInPlace).toBe(true);
  });

  it('round-trips the Data Shares kill-switch when explicitly disabled', () => {
    expect(WorkspaceSettings.parse({ dataSharesInPlace: false }).dataSharesInPlace).toBe(false);
    expect(WorkspaceSettings.safeParse({ dataSharesInPlace: 'nope' }).success).toBe(false);
  });

  it('defaultWorkspaceSettings() equals the parsed defaults', () => {
    expect(defaultWorkspaceSettings()).toEqual(WorkspaceSettings.parse({}));
  });

  it('leaves modelJudgeConsent absent by default (opt-in, never assumed)', () => {
    expect(WorkspaceSettings.parse({}).modelJudgeConsent).toBeUndefined();
  });

  it('round-trips a valid modelJudgeConsent and rejects a malformed one', () => {
    const consent = { acknowledgedAt: ISO, payloadVersion: 1 };
    expect(WorkspaceSettings.parse({ modelJudgeConsent: consent }).modelJudgeConsent).toEqual(
      consent,
    );
    // payloadVersion must be a positive integer; acknowledgedAt an ISO datetime.
    expect(
      WorkspaceSettings.safeParse({ modelJudgeConsent: { acknowledgedAt: ISO, payloadVersion: 0 } })
        .success,
    ).toBe(false);
    expect(
      WorkspaceSettings.safeParse({
        modelJudgeConsent: { acknowledgedAt: 'not-a-date', payloadVersion: 1 },
      }).success,
    ).toBe(false);
  });

  it('accepts a fully onboarded file and rejects unknown enum values', () => {
    expect(
      WorkspaceSettings.safeParse({
        runMode: 'standalone',
        policy: 'warn',
        historicalAccess: 'full',
        onboardedAt: ISO,
      }).success,
    ).toBe(true);
    expect(WorkspaceSettings.safeParse({ runMode: 'nope' }).success).toBe(false);
    expect(WorkspaceSettings.safeParse({ policy: 'delete' }).success).toBe(false);
    expect(WorkspaceSettings.safeParse({ historicalAccess: 'partial' }).success).toBe(false);
  });

  it('accepts both run modes and still rejects an unknown one', () => {
    expect(WorkspaceSettings.parse({}).runMode).toBe('standalone');
    expect(WorkspaceSettings.parse({ runMode: 'attached' }).runMode).toBe('attached');
    // A typo is still an error — the enum was widened, not opened.
    expect(WorkspaceSettings.safeParse({ runMode: 'atached' }).success).toBe(false);
  });

  it('attached means nothing without a descriptor', () => {
    // The mode alone can be set by a hand edit or an interrupted attach.
    // Reporting that as attached would show a connection that does not exist
    // and offer a detach that clears nothing.
    expect(isAttached(WorkspaceSettings.parse({ runMode: 'attached' }))).toBe(false);
    expect(isAttached(WorkspaceSettings.parse({ runMode: 'standalone' }))).toBe(false);
    const attached = WorkspaceSettings.parse({
      runMode: 'attached',
      controlPlane: { endpoint: 'https://aka.example.internal', attachedAt: ISO },
    });
    expect(isAttached(attached)).toBe(true);
  });

  it('a descriptor without the mode is not attached either', () => {
    // The reverse half: a stale descriptor left behind by a failed detach must
    // not resurrect the attachment.
    const s = WorkspaceSettings.parse({
      runMode: 'standalone',
      controlPlane: { endpoint: 'https://aka.example.internal', attachedAt: ISO },
    });
    expect(isAttached(s)).toBe(false);
  });

  it('controlPlaneName prefers the label and falls back to the endpoint', () => {
    expect(controlPlaneName({ endpoint: 'https://x.internal', attachedAt: ISO })).toBe(
      'https://x.internal',
    );
    expect(
      controlPlaneName({ endpoint: 'https://x.internal', label: 'Acme Prod', attachedAt: ISO }),
    ).toBe('Acme Prod');
  });
});

describe('row mappers (tenant-free local store)', () => {
  it('toEventRow converts ISO->epoch, JSON-encodes metadata, and carries no tenant/user', () => {
    const row = toEventRow({
      id: EVENT,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: ISO,
      contentHash: 'hash',
      content: 'a prompt',
      metadata: { sessionId: 'sess-1' },
    });
    expect(row).toMatchObject({
      id: EVENT,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: Date.parse(ISO),
      contentHash: 'hash',
      content: 'a prompt',
    });
    expect(row.metadata).toBe(JSON.stringify({ sessionId: 'sess-1' }));
    // The OSS local store is tenant-free — the row must not carry tenant/user.
    expect(row).not.toHaveProperty('tenantId');
    expect(row).not.toHaveProperty('userId');
  });

  it('toEventRow leaves metadata null when absent', () => {
    const row = toEventRow({
      id: EVENT,
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: ISO,
      contentHash: 'hash',
      content: 'a prompt',
    });
    expect(row.metadata).toBeNull();
  });

  it('toFindingRow splits the span, carries no tenant, and never carries a raw match', () => {
    const row = toFindingRow({
      id: FINDING,
      eventId: EVENT,
      ruleId: 'secrets.aws-access-key',
      category: 'secret',
      severity: 'critical',
      span: { start: 3, end: 9 },
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    });
    expect(row).toMatchObject({
      id: FINDING,
      eventId: EVENT,
      ruleId: 'secrets.aws-access-key',
      category: 'secret',
      severity: 'critical',
      spanStart: 3,
      spanEnd: 9,
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    });
    expect(row).not.toHaveProperty('tenantId');
    // The findings table has no raw column; nothing here should resemble one.
    expect(JSON.stringify(row)).not.toContain('rawMatch');
  });

  it('toFindingRow carries a supplied findingKey through, and coerces an absent one to null (never undefined)', () => {
    const base = {
      id: FINDING,
      eventId: EVENT,
      ruleId: 'secrets.aws-access-key',
      category: 'secret',
      severity: 'critical',
      span: { start: 3, end: 9 },
      maskedMatch: 'AKIA****',
      actionTaken: 'block',
      confidence: 0.99,
    } as const;

    const withKey = toFindingRow({ ...base, findingKey: 'a'.repeat(64) });
    expect(withKey.findingKey).toBe('a'.repeat(64));

    const withoutKey = toFindingRow(base);
    expect(withoutKey.findingKey).toBeNull();
  });
});

// The judge gate, the CLI and the dashboard all decide "has the user consented?"
// through this one predicate, so they cannot drift into disagreeing — the failure
// mode being a settings page that shows "Granted" for a consent the judge is
// already treating as revoked.
describe('isModelJudgeConsentValid', () => {
  const consentAt = (payloadVersion: number) => ({
    acknowledgedAt: ISO,
    payloadVersion,
  });

  it('is false when no consent has been recorded', () => {
    expect(isModelJudgeConsentValid(undefined)).toBe(false);
  });

  it('is true when the consent covers the current payload version', () => {
    expect(isModelJudgeConsentValid(consentAt(MODEL_JUDGE_PAYLOAD_VERSION))).toBe(true);
  });

  // A grant given for a narrower payload must not silently authorize a wider one:
  // bumping the version is how a payload change re-asks the user.
  it('is false for a consent recorded against an older payload version', () => {
    expect(isModelJudgeConsentValid(consentAt(MODEL_JUDGE_PAYLOAD_VERSION - 1))).toBe(false);
  });

  it('is false for a consent recorded against an unknown newer version', () => {
    expect(isModelJudgeConsentValid(consentAt(MODEL_JUDGE_PAYLOAD_VERSION + 1))).toBe(false);
  });

  it('accepts what the schema actually parses out of a settings.json', () => {
    const parsed = WorkspaceSettings.parse({
      modelJudgeConsent: { acknowledgedAt: ISO, payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION },
    });
    expect(isModelJudgeConsentValid(parsed.modelJudgeConsent)).toBe(true);
  });
});
