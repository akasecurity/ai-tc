import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import type { ResponseScanOutcome } from './scan-response.ts';
import { responseEmitPayload, scanResponseFields } from './scan-response.ts';
import type { ScannableResponseField } from './tool-response.ts';

function finding(ruleId: string): CaptureResult['findings'][number] {
  return {
    ruleId,
    category: 'secret',
    severity: 'high',
    span: { start: 0, end: 4 },
    rawMatch: 'AKIA',
    confidence: 1,
  };
}

function result(partial: Partial<CaptureResult>): CaptureResult {
  return { action: 'log', text: null, findings: [], ...partial };
}

function bashFields(response: { stdout: string; stderr: string }): ScannableResponseField[] {
  return [
    { path: ['stdout'], text: response.stdout },
    { path: ['stderr'], text: response.stderr },
  ];
}

describe('scanResponseFields', () => {
  it('passes a clean response through untouched', async () => {
    const response = { stdout: 'out text', stderr: 'err text' };
    const outcome = await scanResponseFields('Bash', response, bashFields(response), () =>
      Promise.resolve(result({})),
    );
    expect(outcome.updated).toBe(response);
    expect(outcome.withheldFindings).toEqual([]);
    expect(outcome.redactedFindings).toEqual([]);
    expect(outcome.warnedFindings).toEqual([]);
  });

  it('withholds only the blocked field and names it in the replacement', async () => {
    const response = { stdout: 'out text', stderr: 'AKIA secret' };
    const outcome = await scanResponseFields('Bash', response, bashFields(response), (text) =>
      Promise.resolve(
        text.includes('AKIA')
          ? result({
              action: 'block',
              findings: [finding('secrets/aws-access-key')],
              blockedReferences: [
                { reference: 'ab12cd', ruleId: 'secrets/aws-access-key', maskedValue: 'A***A' },
              ],
            })
          : result({}),
      ),
    );
    const updated = outcome.updated as { stdout: string; stderr: string };
    expect(updated.stdout).toBe('out text');
    expect(updated.stderr).toContain('[AKA SECURITY] Bash stderr withheld');
    expect(outcome.withheldFindings).toHaveLength(1);
    expect(outcome.blockedReferences.map((r) => r.reference)).toEqual(['ab12cd']);
    expect(outcome.redactedReferences).toEqual([]);
  });

  it('keeps blocked and redacted ledger refs apart so the banner never pairs a withheld framing with a redacted ref', async () => {
    // stdout redacts first (its ref must NOT become the banner ref when
    // stderr's block gives the banner its 'withheld' framing).
    const response = { stdout: 'mail me', stderr: 'AKIA secret' };
    const outcome = await scanResponseFields('Bash', response, bashFields(response), (text) =>
      Promise.resolve(
        text === 'mail me'
          ? result({
              action: 'redact',
              text: '[REDACTED]',
              findings: [finding('core-pii/email')],
              blockedReferences: [
                { reference: 'redact', ruleId: 'core-pii/email', maskedValue: 'j***' },
              ],
            })
          : result({
              action: 'block',
              findings: [finding('secrets/aws-access-key')],
              blockedReferences: [
                { reference: 'block1', ruleId: 'secrets/aws-access-key', maskedValue: 'A***A' },
              ],
            }),
      ),
    );
    expect(outcome.blockedReferences.map((r) => r.reference)).toEqual(['block1']);
    expect(outcome.redactedReferences.map((r) => r.reference)).toEqual(['redact']);
    const updated = outcome.updated as { stdout: string; stderr: string };
    expect(updated.stdout).toBe('[REDACTED]');
    expect(updated.stderr).toContain('withheld');
  });

  it('collects warn findings without rewriting anything', async () => {
    const response = { stdout: 'internal-host', stderr: '' };
    const outcome = await scanResponseFields(
      'Bash',
      response,
      [{ path: ['stdout'], text: 'internal-host' }],
      () => Promise.resolve(result({ action: 'warn', findings: [finding('net/internal-host')] })),
    );
    expect(outcome.updated).toBe(response);
    expect(outcome.warnedFindings).toHaveLength(1);
  });

  it('skips redact rewrites when the runtime returns no text', async () => {
    const response = { stdout: 'x', stderr: '' };
    const outcome = await scanResponseFields(
      'Bash',
      response,
      [{ path: ['stdout'], text: 'x' }],
      () => Promise.resolve(result({ action: 'redact', text: null, findings: [finding('r/one')] })),
    );
    expect(outcome.updated).toBe(response);
    expect(outcome.redactedFindings).toEqual([]);
  });

  it('labels a root-path (string response) replacement as plain output', async () => {
    const outcome = await scanResponseFields(
      'Bash',
      'AKIA secret',
      [{ path: [], text: 'AKIA secret' }],
      () =>
        Promise.resolve(result({ action: 'block', findings: [finding('secrets/aws-access-key')] })),
    );
    expect(outcome.updated).toContain('[AKA SECURITY] Bash output withheld');
  });
});

function outcome(partial: Partial<ResponseScanOutcome>): ResponseScanOutcome {
  return {
    updated: {},
    withheldFindings: [],
    redactedFindings: [],
    warnedFindings: [],
    blockedReferences: [],
    redactedReferences: [],
    ...partial,
  };
}

describe('responseEmitPayload', () => {
  it('returns undefined when nothing was flagged (hook stays silent)', () => {
    expect(responseEmitPayload('Bash', outcome({}))).toBeUndefined();
  });

  it('emits a warn-only systemMessage without updatedToolOutput', () => {
    const payload = responseEmitPayload(
      'Bash',
      outcome({ warnedFindings: [finding('net/internal-host')] }),
    ) as { hookSpecificOutput?: unknown; systemMessage: string };
    expect(payload.hookSpecificOutput).toBeUndefined();
    expect(payload.systemMessage).toContain('net/internal-host');
  });

  it('mixed block+redact: withheld header, split rule lines, and the BLOCKED ref on the approve line', () => {
    const payload = responseEmitPayload(
      'Bash',
      outcome({
        updated: { stdout: '[REDACTED]', stderr: '[withheld]' },
        withheldFindings: [finding('secrets/aws-access-key')],
        redactedFindings: [finding('core-pii/email')],
        // redact ref arrived first in field order — it must NOT win.
        redactedReferences: [
          { reference: 'redref', ruleId: 'core-pii/email', maskedValue: 'j***' },
        ],
        blockedReferences: [
          { reference: 'blkref', ruleId: 'secrets/aws-access-key', maskedValue: 'A***A' },
        ],
      }),
    ) as { hookSpecificOutput: { updatedToolOutput: unknown }; systemMessage: string };
    expect(payload.hookSpecificOutput.updatedToolOutput).toEqual({
      stdout: '[REDACTED]',
      stderr: '[withheld]',
    });
    expect(payload.systemMessage).toContain('Bash output withheld');
    expect(payload.systemMessage).toContain('Withheld: secrets/aws-access-key');
    expect(payload.systemMessage).toContain('Redacted: core-pii/email');
    expect(payload.systemMessage).toContain('aka exception approve blkref');
    expect(payload.systemMessage).not.toContain('redref');
  });

  it('redact-only: redacted header with the redact ref', () => {
    const payload = responseEmitPayload(
      'Bash',
      outcome({
        updated: { stdout: '[REDACTED]', stderr: '' },
        redactedFindings: [finding('core-pii/email')],
        redactedReferences: [
          { reference: 'redref', ruleId: 'core-pii/email', maskedValue: 'j***' },
        ],
      }),
    ) as { systemMessage: string };
    expect(payload.systemMessage).toContain('Bash output redacted');
    expect(payload.systemMessage).toContain('aka exception approve redref');
  });

  it('warn findings alongside a rewrite land on the banner instead of vanishing', () => {
    const payload = responseEmitPayload(
      'Bash',
      outcome({
        updated: { stdout: '[withheld]', stderr: 'internal-host ping' },
        withheldFindings: [finding('secrets/aws-access-key')],
        warnedFindings: [finding('net/internal-host')],
      }),
    ) as { systemMessage: string };
    expect(payload.systemMessage).toContain('Also flagged (warn): net/internal-host');
  });
});
