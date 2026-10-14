// The PostToolUse scan loop and its two channels. Never imports the entry file.
//
// The property this file exists to hold is NEGATIVE: this path scans and
// records, and it must never claim a withhold. Every message is therefore
// asserted for what it says AND for the four claims it may not make, and each
// absence check is paired with a positive control on the same bytes.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  unscannedPastWalkLimitsMessage,
  unscannedTooLargeMessage,
} from '../../src/exception-guidance.ts';
import { responseDecision, scanResponseFields } from '../../src/hooks/scan-response.ts';
import type { ScannableResponseField } from '../../src/hooks/tool-response.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// High-entropy and deliberately NOT credential-shaped — this repository is
// public, and a run-by-run absence check needs entropy rather than a format.
const RAW = 'Xf3Q8tLw6Bn2Ky9Vd5Rj1Ms7Hp0Za4Cu';

function findings(...ruleIds: string[]): CaptureResult['findings'] {
  return ruleIds.map((ruleId) => ({
    ruleId,
    category: 'secret',
    severity: 'high',
    maskedMatch: 'X***u',
    confidence: 'high',
  })) as unknown as CaptureResult['findings'];
}

const REF: BlockedDetectionRef = {
  reference: 'aka-ref-0009',
  maskedValue: 'X***u',
} as unknown as BlockedDetectionRef;

function result(
  action: CaptureResult['action'],
  ruleIds: string[],
  refs?: BlockedDetectionRef[],
): CaptureResult {
  return {
    action,
    findings: findings(...ruleIds),
    text: null,
    ...(refs ? { blockedReferences: refs } : {}),
  };
}

const CLI_FIELD: ScannableResponseField = {
  path: ['textResultForLlm'],
  text: `output containing ${RAW}`,
};
const VSCODE_FIELD: ScannableResponseField = { path: [], text: `output containing ${RAW}` };

function outcomeOf(
  fields: readonly ScannableResponseField[],
  results: CaptureResult[],
  truncated = false,
): ReturnType<typeof scanResponseFields> {
  let i = 0;
  return scanResponseFields('bash', { fields: [...fields], truncated }, () => {
    const next = results[i];
    i += 1;
    if (next === undefined) throw new Error('capture called more times than results supplied');
    return Promise.resolve(next);
  });
}

describe('scanResponseFields', () => {
  it('records every scanned path, finding or not', async () => {
    // "Scanned and found nothing" and "there was nothing to scan" produce the
    // same silence and mean opposite things about whether the hook works.
    const outcome = await outcomeOf([CLI_FIELD], [result('log', [])]);
    expect(outcome.scannedPaths).toEqual([['textResultForLlm']]);
    expect(outcome.blockedFindings).toEqual([]);
    expect(outcome.redactedFindings).toEqual([]);
    expect(outcome.warnedFindings).toEqual([]);
    expect(outcome.toolName).toBe('bash');
  });

  it('scans nothing, and says so, when there are no fields', async () => {
    const outcome = await outcomeOf([], []);
    expect(outcome.scannedPaths).toEqual([]);
  });

  // The three lists are kept apart because the sentence each produces differs.
  // A merged one would render every outcome under the strongest label present.
  it('keeps block, redact and warn findings in separate lists', async () => {
    const outcome = await outcomeOf(
      [CLI_FIELD, CLI_FIELD, CLI_FIELD],
      [result('block', ['r.block']), result('redact', ['r.redact']), result('warn', ['r.warn'])],
    );
    expect(outcome.blockedFindings.map((f) => f.ruleId)).toEqual(['r.block']);
    expect(outcome.redactedFindings.map((f) => f.ruleId)).toEqual(['r.redact']);
    expect(outcome.warnedFindings.map((f) => f.ruleId)).toEqual(['r.warn']);
  });

  it('collects references across fields', async () => {
    const outcome = await outcomeOf(
      [CLI_FIELD, CLI_FIELD],
      [result('block', ['r1'], [REF]), result('warn', ['r2'], [REF])],
    );
    expect(outcome.references).toHaveLength(2);
  });

  it('contributes nothing for log or allow, which tell the user nothing', async () => {
    for (const action of ['log', 'allow'] as const) {
      const outcome = await outcomeOf([CLI_FIELD], [result(action, ['r1'], [REF])]);
      expect(outcome.blockedFindings).toEqual([]);
      expect(outcome.redactedFindings).toEqual([]);
      expect(outcome.warnedFindings).toEqual([]);
      // …and no reference either: there is no decision for one to point at.
      expect(outcome.references).toEqual([]);
      // The positive control — the field really was scanned.
      expect(outcome.scannedPaths).toHaveLength(1);
    }
  });
});

/** What the runtime returns for a field whose bounded scan did not finish. */
function refused(): CaptureResult {
  return { action: 'block', findings: [], text: null, scanIncomplete: 'timeout' };
}

const DELIVERED = 'the output already reached the model unchanged';

describe('a result that was not wholly scanned', () => {
  // A refused field is a `block` with NO findings: a loop that skipped
  // finding-less fields first would read it as clean and say nothing.
  it('reads a refused field as unscanned, not as clean or as a block', async () => {
    const outcome = await outcomeOf([CLI_FIELD], [refused()]);
    expect(outcome.unscanned).toBe(true);
    expect(outcome.completedScans).toBe(0);
    expect(outcome.blockedFindings).toEqual([]);

    const cli = responseDecision('cli', outcome);
    expect(cli.output).toBeNull();
    expect(cli.notice).toBe(unscannedTooLargeMessage('bash result', DELIVERED));
    const vscode = responseDecision('vscode', outcome);
    expect(vscode.output).toEqual({
      systemMessage: unscannedTooLargeMessage('bash result', DELIVERED),
    });
  });

  // A walk-cap truncation is not a timeout: nothing ran out of time, the text
  // was never collected. The sentence has to say which.
  it('reports text the reader left out as past the walk limits, not as a timeout', async () => {
    const outcome = await outcomeOf([], [], true);
    const notice = String(responseDecision('cli', outcome).notice);
    expect(notice).toBe(unscannedPastWalkLimitsMessage('bash result', DELIVERED));
    expect(notice).not.toContain('time limit');
  });

  it('says both when one field timed out and the walk also left text out', async () => {
    const outcome = await outcomeOf([CLI_FIELD], [refused()], true);
    const notice = String(responseDecision('cli', outcome).notice);
    expect(notice).toContain(unscannedTooLargeMessage('bash result', DELIVERED));
    expect(notice).toContain(unscannedPastWalkLimitsMessage('bash result', DELIVERED));
    expectNoEchoOf(notice, RAW);
  });

  it('reads a timed-out field alone as a timeout, not as past the walk limits', async () => {
    const outcome = await outcomeOf([CLI_FIELD], [refused()]);
    const notice = String(responseDecision('cli', outcome).notice);
    expect(notice).toContain('time limit');
    expect(notice).not.toContain('structured result');
  });

  it('names only the unchecked part when another field finished with a finding', async () => {
    const outcome = await outcomeOf(
      [CLI_FIELD, CLI_FIELD],
      [result('warn', ['r.warn']), refused()],
    );
    const notice = String(responseDecision('cli', outcome).notice);
    // Positive control: the finding from the part that was scanned is named.
    expect(notice).toContain('r.warn');
    expect(notice).toContain(unscannedTooLargeMessage('part of the bash result', DELIVERED));
    expect(notice).not.toContain('this bash result');
  });

  it('stays silent for a clean result that was wholly scanned (the control)', async () => {
    const outcome = await outcomeOf([CLI_FIELD], [result('log', [])]);
    expect(outcome.unscanned).toBe(false);
    expect(outcome.completedScans).toBe(1);
    expect(responseDecision('cli', outcome)).toEqual({ output: null });
  });
});

describe('responseDecision', () => {
  it('says nothing when nothing was found, on either dialect', async () => {
    const outcome = await outcomeOf([CLI_FIELD], [result('log', [])]);
    for (const dialect of ['cli', 'vscode'] as const) {
      expect(responseDecision(dialect, outcome)).toEqual({ output: null });
    }
  });

  // THE PER-DIALECT DIFFERENCE, and the only one there is: the words are
  // identical, the CHANNEL is not. The Copilot CLI documents no message field
  // on `postToolUse` output, so the same object there is dropped by the host.
  it('routes the CLI message to stderr and the VS Code one to stdout', async () => {
    const outcome = await outcomeOf([CLI_FIELD], [result('warn', ['generic.secret'])]);
    const cli = responseDecision('cli', outcome);
    const vscode = responseDecision('vscode', outcome);

    expect(cli.output).toBeNull();
    expect(cli.notice).toContain('generic.secret');
    expect(cli.notice).toBe((vscode.output as { systemMessage: string } | null)?.systemMessage);
    expect(vscode.notice).toBeUndefined();
  });

  // THE NEGATIVE PROPERTY. The tool has already run; what is at stake is
  // whether its output reached the model, and on this host it did. A message
  // claiming otherwise would record an enforcement that never happened.
  it.each(['block', 'redact', 'warn'] as const)(
    'never claims a withhold on %s, and says the output reached the model',
    async (action) => {
      const outcome = await outcomeOf([CLI_FIELD], [result(action, ['generic.secret'], [REF])]);
      for (const dialect of ['cli', 'vscode'] as const) {
        const decision = responseDecision(dialect, outcome);
        const text =
          decision.notice ?? (decision.output as { systemMessage: string } | null)?.systemMessage;
        // Positive control first: without it every absence check below is
        // satisfied by a decision that said nothing at all.
        expect(text).toContain('generic.secret');
        expect(text).toContain('bash');
        expect(text).toContain('reached the model');
        expect(text).toMatch(/unchanged/u);

        expect(text).not.toMatch(/never reached|did not reach|withheld|withhold this/iu);
        expect(text).not.toMatch(/\bblocked\b/iu);
        // No verdict on stdout, ever — this hook emits at most a bare message.
        expect(decision.output === null || 'systemMessage' in decision.output).toBe(true);
        expect(JSON.stringify(decision.output ?? {})).not.toContain('modifiedResult');
        expect(JSON.stringify(decision.output ?? {})).not.toContain('"decision"');

        expectNoEchoOf(text, RAW);
      }
    },
  );

  it('reads differently for an unenforced policy than for a warn', async () => {
    // A user whose policy says block has to be able to tell that it did not
    // take effect — which is the whole reason the lists are not merged.
    const blocked = responseDecision(
      'cli',
      await outcomeOf([CLI_FIELD], [result('block', ['r1'])]),
    ).notice;
    const warned = responseDecision(
      'cli',
      await outcomeOf([CLI_FIELD], [result('warn', ['r1'])]),
    ).notice;
    expect(blocked).toBeDefined();
    expect(warned).toBeDefined();
    expect(blocked).not.toBe(warned);
    expect(blocked).toContain('no confirmed way');
    expect(warned).not.toContain('no confirmed way');
  });

  it('names the warn rules alongside an unenforced policy rather than dropping them', async () => {
    const outcome = await outcomeOf(
      [CLI_FIELD, CLI_FIELD],
      [result('block', ['r.block']), result('warn', ['r.warn'])],
    );
    const { notice } = responseDecision('cli', outcome);
    expect(notice).toContain('r.block');
    expect(notice).toContain('r.warn');
  });

  it('carries the exception pointer so a user who meant it can act', async () => {
    const outcome = await outcomeOf([VSCODE_FIELD], [result('block', ['r1'], [REF])]);
    const { output } = responseDecision('vscode', outcome);
    expect((output as { systemMessage: string }).systemMessage).toContain(
      'aka exception approve aka-ref-0009',
    );
  });
});
