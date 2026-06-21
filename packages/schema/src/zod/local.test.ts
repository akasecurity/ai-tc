import { describe, expect, it } from 'vitest';

import {
  defaultWorkspaceSettings,
  toEventRow,
  toFindingRow,
  WORKSPACE_SETTINGS_SPEC_VERSION,
  WorkspaceSettings,
} from './local.ts';

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

  it('defaultWorkspaceSettings() equals the parsed defaults', () => {
    expect(defaultWorkspaceSettings()).toEqual(WorkspaceSettings.parse({}));
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

  it("parses the retired 'attached' runMode value as 'standalone'", () => {
    // Files written by earlier releases must keep loading unchanged otherwise.
    const s = WorkspaceSettings.parse({ runMode: 'attached', policy: 'warn' });
    expect(s.runMode).toBe('standalone');
    expect(s.policy).toBe('warn');
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
