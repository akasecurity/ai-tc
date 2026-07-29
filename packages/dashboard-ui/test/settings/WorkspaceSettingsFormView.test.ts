import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  HANDLING_SECTION_DESCRIPTION,
  HANDLING_SECTION_LABEL,
  HISTORICAL_CHOICES,
  HISTORICAL_SECTION_DESCRIPTION,
  HISTORICAL_SECTION_LABEL,
  MODEL_JUDGE_CHOICES,
  MODEL_JUDGE_SECTION_DESCRIPTION,
  MODEL_JUDGE_SECTION_LABEL,
  POLICY_CHOICES,
  VAULT_CHOICES,
  VAULT_SECTION_DESCRIPTION,
  VAULT_SECTION_LABEL,
  vaultChoiceOf,
  type WorkspaceSettingsFormViewProps,
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

// Every string the form renders: each section's heading and description, and
// each choice's label and description.
const FORM_COPY: Record<string, string> = {
  HANDLING_SECTION_LABEL,
  HANDLING_SECTION_DESCRIPTION,
  HISTORICAL_SECTION_LABEL,
  HISTORICAL_SECTION_DESCRIPTION,
  VAULT_SECTION_LABEL,
  VAULT_SECTION_DESCRIPTION,
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
  ...Object.fromEntries(
    VAULT_CHOICES.flatMap((c) => [
      [`VAULT_CHOICES.${c.value}.label`, c.label],
      [`VAULT_CHOICES.${c.value}.description`, c.description],
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
  });

  // maskText masks the secrets it DETECTS in the context window; non-secret text
  // in that window still crosses. Copy that says the window is masked outright
  // promises more than the engine delivers, so pin the qualified wording.
  it('scopes the masking claim to secrets in the context, not the whole window', () => {
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/secrets in the surrounding context/i);
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/masked/i);
  });

  it('defaults to revoked wording never assuming the grant', () => {
    const revoked = MODEL_JUDGE_CHOICES.find((c) => c.value === 'revoked');
    expect(revoked?.description).toMatch(/never assumed/i);
  });
});

// The vault grant is a custody change: 'on' means detected values survive as
// recoverable ciphertext instead of being destroyed, and the pointers that
// replace them are legible to anyone who can read the files they land in. The
// copy must disclose both, and must not present switching off as an eraser.
describe('WorkspaceSettingsFormView vault-consent section', () => {
  const off = VAULT_CHOICES.find((c) => c.value === 'off');
  const on = VAULT_CHOICES.find((c) => c.value === 'on');

  it('offers exactly the off/on pair, with off marked as the default', () => {
    expect(VAULT_CHOICES.map((c) => c.value)).toEqual(['off', 'on']);
    expect(off?.label).toMatch(/default/i);
  });

  it('derives the current choice from the stored grant: present → on, absent → off', () => {
    expect(vaultChoiceOf(undefined)).toBe('off');
    expect(
      vaultChoiceOf({
        acknowledgedAt: '2026-01-01T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION,
      }),
    ).toBe('on');
  });

  it("discloses what 'on' stores: recoverable copies of secrets, encrypted, on this machine", () => {
    expect(on?.description).toMatch(/recoverable/i);
    expect(on?.description).toMatch(/encrypted/i);
    expect(on?.description).toMatch(/this machine/i);
    expect(on?.description).toMatch(/secrets/i);
  });

  it('discloses what the pointers reveal, and to whom', () => {
    expect(on?.description).toMatch(/where each secret is used/i);
    expect(on?.description).toMatch(/share the same secret/i);
    expect(on?.description).toMatch(/anyone who can read/i);
  });

  it('does not present switching off as an eraser — the CLI purge is', () => {
    expect(on?.description).toMatch(/does not erase/i);
    expect(on?.description).toMatch(/purging the vault from the CLI/i);
  });

  it('keeps the off default free of any storage', () => {
    expect(off?.description).toMatch(/nothing recoverable is stored/i);
  });

  it('emits only the choice string — no acknowledgedAt/version leaves the form', () => {
    // The grant object is stamped by the server action; the form's save payload
    // carries the bare 'off' | 'on' string and nothing a client could forge.
    type Emitted = Parameters<WorkspaceSettingsFormViewProps['onSave']>[0]['vaultConsent'];
    expectTypeOf<Emitted>().toEqualTypeOf<'off' | 'on'>();
  });
});
