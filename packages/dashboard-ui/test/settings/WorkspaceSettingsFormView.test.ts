import type { WorkspaceSettings } from '@akasecurity/schema';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  HANDLING_SECTION_DESCRIPTION,
  HANDLING_SECTION_LABEL,
  HISTORICAL_CHOICES,
  HISTORICAL_SECTION_DESCRIPTION,
  HISTORICAL_SECTION_LABEL,
  INLINE_REVEAL_CHOICES,
  INLINE_REVEAL_SECTION_DESCRIPTION,
  MODEL_JUDGE_CHOICES,
  MODEL_JUDGE_SECTION_DESCRIPTION,
  MODEL_JUDGE_SECTION_LABEL,
  POLICY_CHOICES,
  VAULT_CHOICES,
  VAULT_SECTION_DESCRIPTION,
  VAULT_SECTION_LABEL,
  VAULT_STALE_NOTICE,
  vaultChoiceOf,
  vaultConsentStale,
  WorkspaceSettingsFormView,
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
  MODEL_JUDGE_SECTION_LABEL,
  MODEL_JUDGE_SECTION_DESCRIPTION,
  ...Object.fromEntries(
    MODEL_JUDGE_CHOICES.flatMap((c) => [
      [`MODEL_JUDGE_CHOICES.${c.value}.label`, c.label],
      [`MODEL_JUDGE_CHOICES.${c.value}.description`, c.description],
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
// gates the wizard's history sweep — READING local surfaces, and nothing beyond
// that. Sending what the sweep finds to the model API is the distinct model-judge
// grant below, which the judge checks on every run. So this description has to
// scope itself to the read and hand the egress off to that control: copy that
// folds the two together tells a user who picked Full that they authorized a send
// they did not, and leaves them looking for a revocation lever on the wrong one.
describe('WorkspaceSettingsFormView historical-access copy', () => {
  const full = HISTORICAL_CHOICES.find((c) => c.value === 'full');

  it('offers the full grant', () => {
    expect(full).toBeDefined();
  });

  it('scopes the grant to reading and hands the egress to the separate consent', () => {
    expect(full?.description).toMatch(/reading them only/i);
    expect(full?.description).toMatch(/separate/i);
    expect(full?.description).toMatch(/model-judge consent/i);
  });

  // The earlier copy read "This also lets /aka:setup send what that scan finds —
  // raw values including any secrets and the surrounding transcript text — to the
  // model API". Describing that payload here is what makes the grant look like it
  // authorizes the send, so the payload belongs on the control that does.
  it('does not describe a payload this grant cannot authorize', () => {
    expect(full?.description).not.toMatch(/this also lets/i);
    expect(full?.description).not.toMatch(/raw values/i);
    expect(full?.description).not.toMatch(/transcript text/i);
    // The file path is dropped before egress (toJudgePayload) — no surface may
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

  // This control is the only surface that authorizes the send, so it carries the
  // whole payload disclosure — not a euphemistic "sends findings". "Findings"
  // reads as the masked rows shown elsewhere in the dashboard; what actually
  // crosses is the raw value, a sized window of transcript text, and the labels
  // the finding was scored with.
  //
  // `on either side` is load-bearing, not decoration: CONTEXT_RADIUS is applied
  // to BOTH ends of the match span (history/scan.ts), so the window is ~240
  // characters, not 120. A bare /120 characters/ assertion passes either way —
  // it proves the number is present, not that the claim is true — which is the
  // containment-not-truth failure these guards exist to retire.
  it('names the raw value, the sized context window, and the labels riding with them', () => {
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/raw, unmasked value/i);
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(
      /120 characters of surrounding transcript text on either side/,
    );
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/severity/i);
  });

  it('does not present revocation as a recall of what was already sent', () => {
    expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(/cannot recall/i);
  });

  // The choice a user actually clicks carries the CLASS of data and the SIZE of
  // the window — the two facts that change the decision. The full label
  // enumeration (rule/category/severity/masked value/confidence) stays in the
  // section blurb above: those are non-sensitive, and stacking them into the
  // radio would bury the raw-value warning in a list, making the label less
  // readable rather than more. So this is a deliberate split, not an omission.
  it('names the raw value and the sized window on the grant choice itself', () => {
    const granted = MODEL_JUDGE_CHOICES.find((c) => c.value === 'granted');
    expect(granted?.description).toMatch(/raw, unmasked value/i);
    expect(granted?.description).toMatch(/120 characters of surrounding context on either side/);
    expect(granted?.description).toMatch(/model API/i);
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
    expect(on?.description).toMatch(/purging the vault from the dashboard's Vault page/i);
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

describe('stale vault grant', () => {
  it('is stale only when a grant exists at an older version', () => {
    expect(vaultConsentStale(undefined)).toBe(false);
    expect(
      vaultConsentStale({
        acknowledgedAt: '2026-07-30T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION,
      }),
    ).toBe(false);
    expect(
      vaultConsentStale({
        acknowledgedAt: '2026-07-30T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION - 1,
      }),
    ).toBe(true);
  });

  it('the notice says vaulting is paused and how re-consent happens', () => {
    expect(VAULT_STALE_NOTICE).toContain('paused');
    expect(VAULT_STALE_NOTICE).toContain('re-consent');
  });
});

describe('inline reveal section', () => {
  it('offers the three modes with masked as the labelled default', () => {
    expect(INLINE_REVEAL_CHOICES.map((c) => c.value)).toEqual(['masked', 'full', 'off']);
    expect(INLINE_REVEAL_CHOICES[0]?.label).toContain('default');
  });

  // The full-mode copy is the risk disclosure the consent step defers to — it
  // must name the exposure, the cap, and the audit.
  it('full-mode copy names the risk, the cap, and the audit', () => {
    const full = INLINE_REVEAL_CHOICES.find((c) => c.value === 'full');
    expect(full?.description).toMatch(/shoulder-surfed|screen-shared/);
    expect(full?.description).toContain('two per message');
    expect(full?.description).toContain('audited');
  });

  it('the section states it is display-only', () => {
    expect(INLINE_REVEAL_SECTION_DESCRIPTION).toContain('Display-only');
  });
});

describe('stale grant enables the one-save re-consent', () => {
  const staleSettings: WorkspaceSettings = {
    specVersion: 5,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    vaultConsent: {
      acknowledgedAt: '2020-01-01T00:00:00.000Z',
      version: VAULT_CONSENT_VERSION + 1,
    },
  };

  it('renders the notice AND an enabled Save button, untouched', () => {
    const html = renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, {
        settings: staleSettings,
        onSave: () => undefined,
        busy: false,
      }),
    );
    expect(html).toContain('data-slot="vault-stale-notice"');
    // The documented recovery is ONE save with 'on' selected — so the button
    // must not be disabled by the form starting clean.
    // React renders the boolean attribute as disabled="" — the Tailwind
    // `disabled:` variant classes must not trip this assertion.
    const saveButton = /<button[^>]*>(?:[^<]*Save changes[^<]*)<\/button>/.exec(html)?.[0] ?? '';
    expect(saveButton).not.toBe('');
    expect(saveButton).not.toContain('disabled=""');
  });
});
