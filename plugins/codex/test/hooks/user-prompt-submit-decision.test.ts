// Tests the pure UserPromptSubmit decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
// The spawn-driven suite next door (user-prompt-submit.test.ts) stays as the
// wire contract for the enforcement levels; this one pins the branch a spawn
// cannot reach cheaply: a prompt whose bounded scan did not finish.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { blockMessage, tooLargeToScanMessage } from '../../src/exception-guidance.ts';
import { decideUserPromptSubmit } from '../../src/hooks/user-prompt-submit-decision.ts';

const RULE = 'secrets/twilio-key';

function result(action: CaptureResult['action']): CaptureResult {
  return {
    action,
    text: action === 'block' ? null : 'a prompt',
    findings: [
      {
        ruleId: RULE,
        category: 'secret',
        severity: 'high',
        span: { start: 0, end: 4 },
        rawMatch: 'abcd',
        confidence: 0.95,
      },
    ],
  };
}

describe('decideUserPromptSubmit', () => {
  // A refused prompt arrives as a `block` with no findings, so the ordinary
  // block branch would name no rule ("flagged .") and point at an exception
  // that has nothing to approve.
  it.each(['timeout', 'unavailable'] as const)(
    'blocks a prompt whose bounded scan did not finish (%s) with the too-large reason',
    (scanIncomplete) => {
      expect(
        decideUserPromptSubmit({ action: 'block', text: null, findings: [], scanIncomplete }),
      ).toEqual({ decision: 'block', reason: tooLargeToScanMessage('prompt') });
    },
  );

  it('blocks a flagged prompt with the removal message, for block and redact alike', () => {
    const expected = {
      decision: 'block',
      reason: blockMessage({ subject: 'prompt', ruleIds: RULE }),
    };
    expect(decideUserPromptSubmit(result('block'))).toEqual(expected);
    expect(decideUserPromptSubmit(result('redact'))).toEqual(expected);
  });

  it('warns and lets the prompt continue', () => {
    expect(decideUserPromptSubmit(result('warn'))).toEqual({
      systemMessage: `AKA flagged sensitive content (${RULE}) — sent unchanged.`,
    });
  });

  it('has no opinion on a clean or log-only prompt', () => {
    expect(decideUserPromptSubmit({ action: 'log', text: 'a prompt', findings: [] })).toBeNull();
    expect(decideUserPromptSubmit(result('log'))).toBeNull();
  });
});
