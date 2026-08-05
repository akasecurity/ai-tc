// Tests the pure PostToolUse scan/emit module directly — NEVER via the hook
// entry file. Pins the one real behavioral divergence from Claude Code: Codex
// has no `updatedToolOutput` field, so both `block` AND `redact` outcomes
// collapse into the same whole-result `decision:'block'` withhold — see the
// module comment on scan-response.ts for why a partial in-place splice isn't
// safe to attempt here.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { responseEmitPayload, scanResponseFields } from '../../src/hooks/scan-response.ts';
import type { ScannableResponseField } from '../../src/hooks/tool-response.ts';

type Finding = CaptureResult['findings'][number];

function finding(ruleId: string, rawMatch: string, text: string): Finding {
  const start = text.indexOf(rawMatch);
  return {
    ruleId,
    category: 'secret',
    severity: 'critical',
    span: { start, end: start + rawMatch.length },
    rawMatch,
    confidence: 0.95,
  };
}

describe('scanResponseFields + responseEmitPayload', () => {
  it('a block outcome withholds the whole result via decision:block', async () => {
    const stdout = 'AWS_SECRET_ACCESS_KEY=abcd1234';
    const fields: ScannableResponseField[] = [{ path: ['stdout'], text: stdout }];
    const capture = (): Promise<CaptureResult> =>
      Promise.resolve({
        action: 'block',
        text: null,
        findings: [finding('secrets/aws-secret-key', 'abcd1234', stdout)],
        blockedReferences: [
          { reference: 'aa11bb', ruleId: 'secrets/aws-secret-key', maskedValue: 'a******4' },
        ],
      });

    const outcome = await scanResponseFields('Bash', fields, capture);
    const payload = responseEmitPayload(outcome) as {
      decision: string;
      reason: string;
      systemMessage: string;
    };

    expect(payload.decision).toBe('block');
    expect(payload.reason).toContain('Bash output withheld');
    expect(payload.reason).toContain('secrets/aws-secret-key');
    // The reason string replaces the tool result — it must never leak the raw secret.
    expect(payload.reason).not.toContain('abcd1234');
    expect(payload.systemMessage).toContain('aka exception approve aa11bb');
  });

  it('a redact outcome ALSO withholds via decision:block (no partial splice on Codex)', async () => {
    const stdout = 'db password is hunter2';
    const fields: ScannableResponseField[] = [{ path: ['stdout'], text: stdout }];
    const capture = (): Promise<CaptureResult> =>
      Promise.resolve({
        action: 'redact',
        text: stdout.replace('hunter2', '[REDACTED:SECRET]'),
        findings: [finding('secrets/generic-password', 'hunter2', stdout)],
        blockedReferences: [
          { reference: 'cc22dd', ruleId: 'secrets/generic-password', maskedValue: 'h*****2' },
        ],
      });

    const outcome = await scanResponseFields('Bash', fields, capture);
    const payload = responseEmitPayload(outcome) as { decision: string; reason: string };

    // Escalated, exactly like PreToolUse's redact-on-executable rule — Codex
    // has no field-level splice to fall back to.
    expect(payload.decision).toBe('block');
    expect(payload.reason).not.toContain('hunter2');
    expect(payload.reason).not.toContain('[REDACTED:SECRET]');
  });

  it('a warn-only outcome passes the output through with a systemMessage', async () => {
    const stdout = 'uses share_destination table';
    const fields: ScannableResponseField[] = [{ path: ['stdout'], text: stdout }];
    const capture = (): Promise<CaptureResult> =>
      Promise.resolve({
        action: 'warn',
        text: stdout,
        findings: [finding('core-code-context/db-table-name', 'share_destination', stdout)],
      });

    const outcome = await scanResponseFields('Bash', fields, capture);
    const payload = responseEmitPayload(outcome);

    expect(payload).toEqual({
      systemMessage:
        'AKA flagged sensitive content in Bash output (core-code-context/db-table-name).',
    });
  });

  it('no findings emits nothing (pass through unchanged)', async () => {
    const fields: ScannableResponseField[] = [{ path: ['stdout'], text: 'nothing interesting' }];
    const capture = (): Promise<CaptureResult> =>
      Promise.resolve({
        action: 'log',
        text: 'nothing interesting',
        findings: [],
      });

    const outcome = await scanResponseFields('Bash', fields, capture);
    expect(responseEmitPayload(outcome)).toBeUndefined();
  });
});
