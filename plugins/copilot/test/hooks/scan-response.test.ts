// The PostToolUse scan loop and its two output shapes, driven once per dialect
// at every enforcement level. Never imports the hook entry.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import type { Dialect } from '../../src/hooks/dialect.ts';
import { responseEmitPayload, scanResponseFields } from '../../src/hooks/scan-response.ts';
import type { ScannableResponseField } from '../../src/hooks/tool-response.ts';

// A high-entropy fixture that matches no shipped rule: this repository is
// public, so nothing here may look like a real credential.
const RAW = 'qZ4tLm8xPv2wRk6nBd3yHc9sJf5gTa7e';
const MASKED = 'q******e';

function capture(
  action: CaptureResult['action'],
  opts: { ruleId?: string; text?: string | null } = {},
): CaptureResult {
  return {
    action,
    findings: [{ ruleId: opts.ruleId ?? 'generic-secret' }],
    text: opts.text === undefined ? MASKED : opts.text,
    blockedReferences: [{ reference: 'BR-1', maskedValue: MASKED }],
  } as unknown as CaptureResult;
}

function clean(): CaptureResult {
  return { action: 'log', findings: [], text: null } as unknown as CaptureResult;
}

/** The CLI's recorded result envelope, with the scannable field carrying RAW. */
function cliResult(): Record<string, unknown> {
  return { resultType: 'success', textResultForLlm: `token ${RAW}` };
}

const CLI_FIELDS: ScannableResponseField[] = [{ path: ['textResultForLlm'], text: `token ${RAW}` }];
const VSCODE_FIELDS: ScannableResponseField[] = [{ path: [], text: `token ${RAW}` }];

function fieldsFor(dialect: Dialect): ScannableResponseField[] {
  return dialect === 'vscode' ? VSCODE_FIELDS : CLI_FIELDS;
}

function responseFor(dialect: Dialect): unknown {
  return dialect === 'vscode' ? `token ${RAW}` : cliResult();
}

async function outcomeOf(
  dialect: Dialect,
  result: CaptureResult,
): Promise<ReturnType<typeof scanResponseFields>> {
  return scanResponseFields('bash', fieldsFor(dialect), () => Promise.resolve(result));
}

describe('scanResponseFields', () => {
  it('records every scanned path, whether or not it found anything', async () => {
    const outcome = await outcomeOf('cli', clean());
    expect(outcome.scannedPaths).toEqual([['textResultForLlm']]);
    expect(outcome.withheldFindings).toEqual([]);
    expect(outcome.rewrites).toEqual([]);
  });

  it('keeps the masked text a redact produced, for the host that can use it', async () => {
    const outcome = await outcomeOf('cli', capture('redact'));
    expect(outcome.redactedFindings).toHaveLength(1);
    expect(outcome.rewrites).toEqual([{ path: ['textResultForLlm'], text: MASKED }]);
  });

  /**
   * A redact whose masked form never arrived has nothing to substitute.
   * Passing the original through under a "redacted" note would send the raw
   * value and report it as masked, so it joins the withheld bucket instead.
   */
  it('withholds a redact that produced no masked text', async () => {
    const outcome = await outcomeOf('cli', capture('redact', { text: null }));
    expect(outcome.redactedFindings).toEqual([]);
    expect(outcome.withheldFindings).toHaveLength(1);
    expect(outcome.rewrites).toEqual([]);
  });
});

describe('responseEmitPayload — CLI', () => {
  it('says nothing when nothing was flagged', async () => {
    const outcome = await outcomeOf('cli', clean());
    expect(responseEmitPayload('cli', outcome, cliResult())).toBeUndefined();
  });

  it('substitutes the masked text in place for a redact', async () => {
    const outcome = await outcomeOf('cli', capture('redact'));
    const payload = responseEmitPayload('cli', outcome, cliResult());
    expect(payload).toEqual({
      modifiedResult: { resultType: 'success', textResultForLlm: MASKED },
    });
  });

  /**
   * A block has no masked text, so nothing in `rewrites` names the field it
   * came from. The withhold notice must still land ON that field — otherwise
   * the blocked value goes to the model untouched, which is the whole failure
   * the withhold exists to prevent.
   */
  it('overwrites the scanned field with the withhold notice for a block', async () => {
    const outcome = await outcomeOf('cli', capture('block'));
    const payload = responseEmitPayload('cli', outcome, cliResult()) as {
      modifiedResult: Record<string, unknown>;
    };
    expect(payload.modifiedResult.resultType).toBe('success');
    const text = payload.modifiedResult.textResultForLlm as string;
    expect(text).toContain('[AKA SECURITY]');
    expect(text).toContain('generic-secret');
    expect(text).not.toContain(RAW);
  });

  it('notes a warn without rewriting anything', async () => {
    const outcome = await outcomeOf('cli', capture('warn'));
    const payload = responseEmitPayload('cli', outcome, cliResult());
    expect(payload).not.toHaveProperty('modifiedResult');
    expect((payload as { systemMessage: string }).systemMessage).toContain('generic-secret');
  });

  /**
   * `modifiedResult` has to be an object, so a result that is not one cannot
   * be rebuilt. The degrade must NOT use the withheld banner: that text states
   * the flagged value never reached the model, and on this branch nothing was
   * replaced at all.
   */
  it('degrades to an honest note when the result cannot be rewritten', async () => {
    const outcome = await scanResponseFields('bash', [{ path: [], text: `token ${RAW}` }], () =>
      Promise.resolve(capture('block')),
    );
    const payload = responseEmitPayload('cli', outcome, 'a bare string result');
    const message = (payload as { systemMessage: string }).systemMessage;
    expect(payload).not.toHaveProperty('modifiedResult');
    expect(message).toContain('cannot rewrite');
    expect(message).toContain('unchanged');
    expect(message).not.toContain('never reached the model');
  });
});

describe('responseEmitPayload — VS Code', () => {
  it('says nothing when nothing was flagged', async () => {
    const outcome = await outcomeOf('vscode', clean());
    expect(responseEmitPayload('vscode', outcome, responseFor('vscode'))).toBeUndefined();
  });

  it('withholds the whole result for a block', async () => {
    const outcome = await outcomeOf('vscode', capture('block'));
    const payload = responseEmitPayload('vscode', outcome, responseFor('vscode')) as {
      decision: string;
      additionalContext: string;
    };
    expect(payload.decision).toBe('block');
    expect(payload.additionalContext).toContain('generic-secret');
    expect(payload.additionalContext).not.toContain(RAW);
  });

  /**
   * THE PER-HOST DIFFERENCE, driven rather than described. VS Code has no
   * result-rewrite field, so a redact escalates to the same whole-result
   * withhold a block gets — while the CLI, on the identical outcome,
   * substitutes the masked text in place.
   */
  it('escalates a redact to a withhold, where the CLI redacts in place', async () => {
    const vscode = responseEmitPayload(
      'vscode',
      await outcomeOf('vscode', capture('redact')),
      responseFor('vscode'),
    );
    const cli = responseEmitPayload('cli', await outcomeOf('cli', capture('redact')), cliResult());

    expect(vscode).toHaveProperty('decision', 'block');
    expect(vscode).not.toHaveProperty('modifiedResult');
    expect(cli).toHaveProperty('modifiedResult');
    expect(cli).not.toHaveProperty('decision');
  });

  it('notes a warn without withholding', async () => {
    const outcome = await outcomeOf('vscode', capture('warn'));
    const payload = responseEmitPayload('vscode', outcome, responseFor('vscode'));
    expect(payload).not.toHaveProperty('decision');
    expect((payload as { systemMessage: string }).systemMessage).toContain('generic-secret');
  });
});
