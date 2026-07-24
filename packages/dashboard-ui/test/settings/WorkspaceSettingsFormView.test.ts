import { describe, expect, it } from 'vitest';

import {
  HANDLING_SECTION_DESCRIPTION,
  MODEL_JUDGE_CHOICES,
  MODEL_JUDGE_SECTION_DESCRIPTION,
  MODEL_JUDGE_SECTION_LABEL,
  POLICY_CHOICES,
} from '../../src/settings/WorkspaceSettingsFormView.tsx';

// The global handling toggle (settings.policy) no longer drives runtime
// enforcement — per-category Policies do. Guard against the copy regressing to
// the old claims that this control has a live, altering effect.
describe('WorkspaceSettingsFormView handling copy', () => {
  const allCopy = [HANDLING_SECTION_DESCRIPTION, ...POLICY_CHOICES.map((c) => c.description)].join(
    ' ',
  );

  it('drops the now-false "nothing is altered" claim', () => {
    expect(allCopy).not.toMatch(/nothing is altered/i);
  });

  it('drops the now-false "takes effect on the next hook" claim', () => {
    expect(allCopy).not.toMatch(/takes effect on the next hook/i);
    expect(allCopy).not.toMatch(/next hook/i);
  });

  it('points enforcement at the per-category Policies', () => {
    expect(HANDLING_SECTION_DESCRIPTION).toMatch(/Policies/);
    expect(HANDLING_SECTION_DESCRIPTION).toMatch(/per-category/i);
  });
});

// The model-judge consent control is a DISTINCT grant from historical access.
// Its copy must make that separation clear and disclose what leaves the machine.
describe('WorkspaceSettingsFormView model-judge consent control', () => {
  it('offers exactly a grant and a revoke choice', () => {
    expect(MODEL_JUDGE_CHOICES.map((c) => c.value).sort()).toEqual(['granted', 'revoked']);
  });

  it('labels the section as its own consent, separate from historical access', () => {
    expect(MODEL_JUDGE_SECTION_LABEL).toMatch(/model-judge/i);
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/separate consent from historical access/i);
  });

  it('discloses that findings go to the model API while the file path is not sent', () => {
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/model API/);
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/file path is never sent/i);
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/masked/i);
  });

  it('defaults to revoked wording never assuming the grant', () => {
    const revoked = MODEL_JUDGE_CHOICES.find((c) => c.value === 'revoked');
    expect(revoked?.description).toMatch(/never assumed/i);
  });
});
