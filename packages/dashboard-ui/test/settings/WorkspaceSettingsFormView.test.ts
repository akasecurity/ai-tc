import { describe, expect, it } from 'vitest';

import {
  HANDLING_SECTION_DESCRIPTION,
  HISTORICAL_CHOICES,
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

// Granting 'full' here is the same consent the /aka:setup wizard collects, and it
// is what gates the wizard's history sweep — whose judge step sends raw findings
// to the model API. The wizard's own copy points users at this screen for scope
// and revocation, so a description that stops at "may be scanned" would leave the
// egress disclosed in one place and hidden in the other.
describe('WorkspaceSettingsFormView historical-access copy', () => {
  const full = HISTORICAL_CHOICES.find((c) => c.value === 'full');

  it('offers the full grant', () => {
    expect(full).toBeDefined();
  });

  it('discloses the model-API egress the grant enables', () => {
    expect(full?.description).toMatch(/model API/i);
    expect(full?.description).toMatch(/raw values/i);
    expect(full?.description).toMatch(/secrets/i);
  });

  it('names the rest of the payload, not just the secret', () => {
    expect(full?.description).toMatch(/transcript text/i);
    expect(full?.description).toMatch(/file path/i);
  });

  it('does not present revocation as a recall', () => {
    expect(full?.description).toMatch(/cannot recall/i);
  });

  it('leaves the session-only default free of any egress', () => {
    const sessionOnly = HISTORICAL_CHOICES.find((c) => c.value === 'session-only');
    expect(sessionOnly?.description).not.toMatch(/model API/i);
  });
});
