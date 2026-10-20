import { describe, expect, it } from 'vitest';

import {
  LABEL_REPORT_BATCH_MAX,
  LabelReportAck,
  LabelReportRequest,
  ReportedDismissal,
  ReportedGrant,
} from '../../src/zod/label-report.ts';

const grant = {
  id: '00000000-0000-4000-8000-000000000001',
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  keyVersion: 1,
  maskedValue: 'A••••••••••••••Q',
  capability: 'suppress',
  scope: 'once',
  expiresAt: null,
  maxUses: 1,
  useCount: 0,
  lastUsedAt: null,
  method: 'test-or-example',
  confirmedBy: 'user',
  createdVia: 'cli-approve',
  createdAt: '2026-10-19T10:00:00.000Z',
  updatedAt: '2026-10-19T10:00:00.000Z',
  revokedAt: null,
};

const dismissal = {
  id: '00000000-0000-4000-8000-000000000002',
  findingKey: 'fk-1',
  method: 'false-positive',
  confirmedBy: 'user',
  resolvedAt: 1_766_000_000_000,
};

describe('ReportedGrant', () => {
  it('parses a grant with its label', () => {
    expect(ReportedGrant.parse(grant)).toEqual(grant);
  });

  it('accepts an unlabelled grant', () => {
    expect(ReportedGrant.safeParse({ ...grant, method: null }).success).toBe(true);
  });

  // Labels only: anything a person typed, and the keyed fingerprint, are refused
  // rather than stripped, so a sender that adds one fails instead of shipping it.
  it.each([
    ['justification', 'typed by the developer'],
    ['revokeReason', 'typed by the developer'],
    ['revokedBy', 'os-user'],
    ['createdBy', 'os-user'],
    ['valueFingerprint', 'a'.repeat(64)],
    ['conditions', null],
  ])('refuses %s', (field, value) => {
    expect(ReportedGrant.safeParse({ ...grant, [field]: value }).success).toBe(false);
  });

  it('refuses a machine verdict as the label', () => {
    expect(ReportedGrant.safeParse({ ...grant, method: 'exception' }).success).toBe(false);
  });
});

describe('ReportedDismissal', () => {
  it('parses a person’s dismissal', () => {
    expect(ReportedDismissal.parse(dismissal)).toEqual(dismissal);
  });

  it('refuses the free-text evidence and a machine verdict', () => {
    expect(ReportedDismissal.safeParse({ ...dismissal, evidence: 'x' }).success).toBe(false);
    expect(ReportedDismissal.safeParse({ ...dismissal, method: 'redetected' }).success).toBe(false);
  });
});

describe('LabelReportRequest', () => {
  it('parses a batch of grants and dismissals, either side empty', () => {
    expect(LabelReportRequest.safeParse({ grants: [grant], dismissals: [] }).success).toBe(true);
    expect(LabelReportRequest.safeParse({ grants: [], dismissals: [dismissal] }).success).toBe(
      true,
    );
  });

  it('refuses an empty report and one over the batch limit', () => {
    expect(LabelReportRequest.safeParse({ grants: [], dismissals: [] }).success).toBe(false);
    const many = Array.from({ length: LABEL_REPORT_BATCH_MAX + 1 }, () => dismissal);
    expect(LabelReportRequest.safeParse({ grants: [], dismissals: many }).success).toBe(false);
  });

  it('carries no device id: the deployment takes it from the credential', () => {
    expect(
      LabelReportRequest.safeParse({ deviceId: 'd', grants: [grant], dismissals: [] }).success,
    ).toBe(false);
  });
});

describe('LabelReportAck', () => {
  it('counts what was recorded', () => {
    expect(LabelReportAck.parse({ grants: 1, dismissals: 0 })).toEqual({
      grants: 1,
      dismissals: 0,
    });
  });
});
