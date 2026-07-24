import { describe, expect, it } from 'vitest';

import { SETTINGS_PAGE_SUB } from '../../src/settings/copy.ts';
import {
  HANDLING_SECTION_DESCRIPTION,
  POLICY_CHOICES,
} from '../../src/settings/WorkspaceSettingsFormView.tsx';

// The global handling toggle (settings.policy) no longer drives runtime
// enforcement — per-category Policies do. Guard against the copy regressing to
// the old claims that this control has a live, altering effect. The page head is
// covered too: it sits above the form and makes the same promise.
describe('Settings copy', () => {
  const allCopy = [
    SETTINGS_PAGE_SUB,
    HANDLING_SECTION_DESCRIPTION,
    ...POLICY_CHOICES.map((c) => c.description),
  ].join(' ');

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

  it('describes the page-head knobs as stored, not applied', () => {
    expect(SETTINGS_PAGE_SUB).toMatch(/stored/i);
    expect(SETTINGS_PAGE_SUB).not.toMatch(/applied/i);
    expect(SETTINGS_PAGE_SUB).toMatch(/Policies/);
  });
});
