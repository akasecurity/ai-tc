import { describe, expect, it } from 'vitest';

import {
  HANDLING_SECTION_DESCRIPTION,
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
