// Tests the pure PostToolUse scan/emit module directly — NEVER via the hook
// entry file. Pins the one real behavioral divergence from Claude Code: Codex
// has no `updatedToolOutput` field, so both `block` AND `redact` outcomes
// collapse into the same whole-result `decision:'block'` withhold — see the
// module comment on scan-response.ts for why a partial in-place splice isn't
// safe to attempt here.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { tooLargeToolText } from '../../src/exception-guidance.ts';
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

describe('scanResponseFields — deadline', () => {
  const fields: ScannableResponseField[] = [
    { path: [0, 'text'], text: 'first' },
    { path: [1, 'text'], text: 'second' },
    { path: [2, 'text'], text: 'third' },
  ];

  it('starts no capture past the deadline and reports what it left unscanned', async () => {
    let clock = 0;
    const seen: string[] = [];
    const outcome = await scanResponseFields(
      'mcp__s__t',
      fields,
      (text) => {
        seen.push(text);
        clock += 10;
        return Promise.resolve({ action: 'log', text: null, findings: [] });
      },
      { at: 20, now: () => clock },
    );
    expect(seen).toEqual(['first', 'second']);
    expect(outcome.unscannedFields).toBe(1);
  });

  it('reports nothing unscanned while inside the deadline', async () => {
    const outcome = await scanResponseFields(
      'mcp__s__t',
      fields,
      () => Promise.resolve({ action: 'log', text: null, findings: [] }),
      { at: 1, now: () => 0 },
    );
    expect(outcome.unscannedFields).toBe(0);
  });
});

// A field whose bounded large-input scan did not finish is `block` with
// `scanIncomplete` set and NO findings: the no-findings skip would pass it to
// the model unscanned, so it is checked first and the result withheld. Codex
// has no field-level splice, so it goes the way a flagged field does: the
// whole result is replaced by `reason`.
describe('a field whose bounded scan did not finish', () => {
  const fields: ScannableResponseField[] = [
    { path: ['stdout'], text: 'a very large output' },
    { path: ['stderr'], text: 'err text' },
  ];
  const capture = (scanIncomplete: 'timeout' | 'unavailable') => (text: string) =>
    Promise.resolve<CaptureResult>(
      text === 'a very large output'
        ? { action: 'block', text: null, findings: [], scanIncomplete }
        : { action: 'log', text: null, findings: [] },
    );

  it.each(['timeout', 'unavailable'] as const)(
    'withholds the result with the too-large reason (%s)',
    async (scanIncomplete) => {
      const outcome = await scanResponseFields('Bash', fields, capture(scanIncomplete));
      expect(outcome.tooLargeFields).toEqual(['stdout']);
      expect(outcome.withheldFindings).toEqual([]);
      expect(outcome.unscannedFields).toBe(0);

      const payload = responseEmitPayload(outcome) as {
        decision: string;
        reason: string;
        systemMessage: string;
      };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toBe(tooLargeToolText('Bash'));
      expect(payload.reason).not.toContain('a very large output');
      expect(payload.systemMessage).toContain('Too large to scan in time: stdout');
      // No rule ran to completion, so nothing an exception could approve.
      expect(payload.systemMessage).not.toContain('aka exception approve');
    },
  );
});

// A refused field beside a redact-escalated one, nothing blocked outright. Codex
// withholds the whole result either way, so the banner is a withhold — and the
// redact's ledger row is the only one there is, so the approve line must carry
// it rather than degrade to the bare command.
describe('a refused field beside a redacted one', () => {
  it('keeps the redact ref on the approve line', async () => {
    const email = ['user1', 'example.com'].join('@');
    const stderr = `contact ${email}`;
    const fields: ScannableResponseField[] = [
      { path: ['stdout'], text: 'a very large output' },
      { path: ['stderr'], text: stderr },
    ];
    const outcome = await scanResponseFields('Bash', fields, (text) =>
      Promise.resolve<CaptureResult>(
        text === 'a very large output'
          ? { action: 'block', text: null, findings: [], scanIncomplete: 'timeout' }
          : {
              action: 'redact',
              text: null,
              findings: [finding('core-pii/email', email, stderr)],
              blockedReferences: [
                { reference: 'redref', ruleId: 'core-pii/email', maskedValue: 'u***' },
              ],
            },
      ),
    );
    expect(outcome.tooLargeFields).toEqual(['stdout']);

    const payload = responseEmitPayload(outcome) as {
      decision: string;
      reason: string;
      systemMessage: string;
    };
    expect(payload.decision).toBe('block');
    // A flagged rule is the more specific reason when there is one.
    expect(payload.reason).toContain('core-pii/email');
    expect(payload.systemMessage).toContain('Redacted: core-pii/email');
    expect(payload.systemMessage).toContain('Too large to scan in time: stdout');
    expect(payload.systemMessage).toContain('(u***) intentionally: aka exception approve redref');
  });
});
