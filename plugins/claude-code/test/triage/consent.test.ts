import type { WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { isModelJudgeConsentValid, MODEL_JUDGE_PAYLOAD_VERSION } from '../../src/triage/consent.ts';

describe('isModelJudgeConsentValid', () => {
  it('is false when no consent has been recorded', () => {
    expect(isModelJudgeConsentValid(undefined)).toBe(false);
  });

  it('is true when consent matches the current payload version', () => {
    const consent: WorkspaceSettings['modelJudgeConsent'] = {
      acknowledgedAt: new Date().toISOString(),
      payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION,
    };
    expect(isModelJudgeConsentValid(consent)).toBe(true);
  });

  it('is false when the recorded consent is for a stale/mismatched payload version', () => {
    const consent: WorkspaceSettings['modelJudgeConsent'] = {
      acknowledgedAt: new Date().toISOString(),
      payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION + 1,
    };
    expect(isModelJudgeConsentValid(consent)).toBe(false);
  });
});
