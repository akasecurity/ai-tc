import { describe, expect, it } from 'vitest';

import {
  HANDLING_SECTION_DESCRIPTION,
  HANDLING_SECTION_LABEL,
  HISTORICAL_CHOICES,
  HISTORICAL_SECTION_DESCRIPTION,
  HISTORICAL_SECTION_LABEL,
  POLICY_CHOICES,
} from '../../src/settings/WorkspaceSettingsFormView.tsx';

// Nothing on this page happens on a hook, and nothing happens the moment it is
// saved: settings.policy is a stored default that drives no runtime enforcement
// (per-category Policies do), and historical access is a consent grant read when
// a scan runs. So these four phrasings are false whichever control they describe.
//
// web-ui/test/pages/settings-page-head.test.ts bans these plus a verb class
// (takes effect / applied / enforced) on the page subtitle. That extra ban is
// deliberately NOT applied here: the subtitle speaks for every control at once,
// so any live-effect verb in it is false, while a section describes one control
// and may legitimately say when that control takes effect. The lists are
// duplicated rather than shared because @akasecurity/dashboard-ui exposes only
// src/, and the CLI inlines that whole package — exporting a ban list would ship
// test-only constants in the published binary.
const ALWAYS_FALSE = [/next hook/i, /nothing is altered/i, /immediately/i, /right away/i];

// Every string the form renders: both section headings, both section
// descriptions, and each choice's label and description.
const FORM_COPY: Record<string, string> = {
  HANDLING_SECTION_LABEL,
  HANDLING_SECTION_DESCRIPTION,
  HISTORICAL_SECTION_LABEL,
  HISTORICAL_SECTION_DESCRIPTION,
  ...Object.fromEntries(
    POLICY_CHOICES.flatMap((c) => [
      [`POLICY_CHOICES.${c.value}.label`, c.label],
      [`POLICY_CHOICES.${c.value}.description`, c.description],
    ]),
  ),
  ...Object.fromEntries(
    HISTORICAL_CHOICES.flatMap((c) => [
      [`HISTORICAL_CHOICES.${c.value}.label`, c.label],
      [`HISTORICAL_CHOICES.${c.value}.description`, c.description],
    ]),
  ),
};

describe('WorkspaceSettingsFormView copy', () => {
  it.each(Object.entries(FORM_COPY))('%s claims no live, altering effect', (_name, text) => {
    for (const claim of ALWAYS_FALSE) expect(text).not.toMatch(claim);
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
    // The file path is dropped before egress (toJudgePayload) — copy must not
    // claim it crosses.
    expect(full?.description).not.toMatch(/file path/i);
  });

  it('does not present revocation as a recall', () => {
    expect(full?.description).toMatch(/cannot recall/i);
  });

  it('leaves the session-only default free of any egress', () => {
    const sessionOnly = HISTORICAL_CHOICES.find((c) => c.value === 'session-only');
    expect(sessionOnly?.description).not.toMatch(/model API/i);
  });
});
