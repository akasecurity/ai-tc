import type { CredentialState, WorkspaceSettings } from '@akasecurity/schema';
import {
  BUILTIN_POLICIES,
  HISTORY_SYNC_PAYLOAD_VERSION,
  KNOWN_BUILTIN_IDS,
  TriageHit,
  VAULT_CONSENT_VERSION,
} from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  ATTACH_KEY_HINT,
  canAttach,
  CONNECTION_ATTACHED_DESCRIPTION,
  CONNECTION_ATTACHED_LABEL,
  CONNECTION_CREDENTIAL_MISSING_NOTICE,
  CONNECTION_CREDENTIAL_UNUSABLE_NOTICE,
  CONNECTION_FORWARDING_NOTICE,
  CONNECTION_INACTIVE_BADGE,
  CONNECTION_STANDALONE_DESCRIPTION,
  CONNECTION_UNAVAILABLE_NOTICE,
  DETACH_EXPLANATION,
  DETACH_MANAGED_NOTICE,
  HANDLING_SECTION_DESCRIPTION,
  HANDLING_SECTION_LABEL,
  HANDLING_SECTION_LINK_LABEL,
  HISTORICAL_CHOICES,
  HISTORICAL_SECTION_DESCRIPTION,
  HISTORICAL_SECTION_LABEL,
  HISTORY_SYNC_CHOICES,
  HISTORY_SYNC_SECTION_DESCRIPTION,
  HISTORY_SYNC_SECTION_LABEL,
  HISTORY_SYNC_STALE_BADGE,
  HISTORY_SYNC_STALE_NOTICE,
  INLINE_REVEAL_CHOICES,
  INLINE_REVEAL_SECTION_DESCRIPTION,
  MODEL_JUDGE_CHOICES,
  MODEL_JUDGE_SECTION_DESCRIPTION,
  MODEL_JUDGE_SECTION_LABEL,
  submitAttach,
  VAULT_CHOICES,
  VAULT_SECTION_DESCRIPTION,
  VAULT_SECTION_LABEL,
  VAULT_STALE_BADGE,
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
  // The connection strings are swept like every other section's. They were the
  // one block of copy in this file with no honesty coverage at all, and the
  // attached description shipped claiming an exchange this build never performs.
  CONNECTION_STANDALONE_DESCRIPTION,
  CONNECTION_ATTACHED_DESCRIPTION,
  CONNECTION_FORWARDING_NOTICE,
  CONNECTION_UNAVAILABLE_NOTICE,
  CONNECTION_CREDENTIAL_MISSING_NOTICE,
  CONNECTION_CREDENTIAL_UNUSABLE_NOTICE,
  DETACH_MANAGED_NOTICE,
  HISTORICAL_SECTION_LABEL,
  HISTORICAL_SECTION_DESCRIPTION,
  VAULT_SECTION_LABEL,
  VAULT_SECTION_DESCRIPTION,
  HANDLING_SECTION_LINK_LABEL,
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
  HISTORY_SYNC_SECTION_LABEL,
  HISTORY_SYNC_SECTION_DESCRIPTION,
  ...Object.fromEntries(
    HISTORY_SYNC_CHOICES.flatMap((c) => [
      [`HISTORY_SYNC_CHOICES.${c.value}.label`, c.label],
      [`HISTORY_SYNC_CHOICES.${c.value}.description`, c.description],
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

  it('points enforcement at the per-detection assignment, and offers no control', () => {
    // The pointer names the axis that actually decides — the PER-DETECTION
    // assignment (installed_packs.policy_id), which is the only one that can
    // carry every archetype. It used to say "per-category Policies", which is a
    // different axis: that one stores an ActionTaken and cannot express
    // Redact & Vault at all.
    expect(HANDLING_SECTION_DESCRIPTION).toMatch(/per detection/i);
    expect(HANDLING_SECTION_DESCRIPTION).toMatch(/Detections page/);
    // And it is explicit that no global handling setting exists, because one
    // did, it drove nothing, and users read it as if it did.
    expect(HANDLING_SECTION_DESCRIPTION).toMatch(/no global handling setting/i);
  });

  it('names every built-in archetype in the enforcement pointer', () => {
    // A user sent to the Detections page should already know what they will be
    // choosing between. Derived from the catalog so an added archetype fails
    // here rather than being silently absent from the one sentence that lists
    // them.
    for (const id of KNOWN_BUILTIN_IDS) {
      expect(HANDLING_SECTION_DESCRIPTION, `${id} is not named`).toContain(
        BUILTIN_POLICIES[id].name,
      );
    }
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

  // Derived from the schema rather than pinned to a phrase. `toJudgePayload` is
  // disclosed-by-default — `{ ...hit }` minus three deletes — so a new TriageHit
  // field crosses to the model API with no code edit. The plugin's
  // judge.test.ts classification case is the only other exhaustiveness guard, and
  // a one-line append to its DISCLOSED list silences it without moving any copy
  // assertion. This table is what makes a widened payload red on the control that
  // authorizes the send, which is what CLAUDE.md §4 promises.
  //
  // Copied here rather than shared with the plugin's suites: this is a separate
  // package and words the same fields differently, the same reason expectNoEchoOf
  // is copied rather than imported (CLAUDE.md, Testing).
  const BLURB_DISCLOSURE: Record<keyof typeof TriageHit.shape, RegExp | null> = {
    rawMatch: /raw, unmasked value/i,
    context: /transcript text on either side/i,
    ruleId: /\brule\b/i,
    category: /category/i,
    severity: /severity/i,
    maskedMatch: /masked value/i,
    confidence: /confidence/i,
    id: /counter/i,
    // Dropped by toJudgePayload before egress — nothing to disclose.
    filePath: null,
    valueFingerprint: null,
    keyVersion: null,
  };

  it('classifies every TriageHit field as named-in-the-blurb or dropped', () => {
    expect(Object.keys(BLURB_DISCLOSURE).sort()).toEqual(Object.keys(TriageHit.shape).sort());
  });

  it.each(Object.entries(BLURB_DISCLOSURE).filter((e): e is [string, RegExp] => e[1] !== null))(
    'names the disclosed field %s',
    (_field, pattern) => {
      expect(MODEL_JUDGE_SECTION_DESCRIPTION).toMatch(pattern);
    },
  );

  // The choice a user actually clicks carries the CLASS of data and the SIZE of
  // the window — the two facts that change the decision. The full label
  // enumeration (rule/category/severity/masked value/confidence/counter) stays in
  // the section blurb above, where the schema table enforces it: those are
  // non-sensitive, and stacking them into the radio would bury the raw-value
  // warning in a list, making the label less readable rather than more. So this is
  // a deliberate split, not an omission.
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
    // Present in the markup is NOT the same as visible: a collapsed <details>
    // still renders its children, so the notice must be inside a row the
    // browser has actually opened. Without this the whole warning can be
    // hidden by default and every assertion here stays green.
    const staleRow = html.slice(0, html.indexOf('data-slot="vault-stale-notice"'));
    const rowOpen = staleRow.lastIndexOf('<details');
    expect(staleRow.slice(rowOpen, staleRow.indexOf('>', rowOpen) + 1)).toContain('open');
    // And the collapsed SUMMARY carries the contradiction too, because the row
    // otherwise reads "Allow vaulting" on a machine where vaulting is paused.
    expect(html).toContain('data-slot="row-alert"');
    expect(html).toContain(VAULT_STALE_BADGE);
    // The documented recovery is ONE save with 'on' selected — so the button
    // must not be disabled by the form starting clean.
    // React renders the boolean attribute as disabled="" — the Tailwind
    // `disabled:` variant classes must not trip this assertion.
    const saveButton = /<button[^>]*>(?:[^<]*Save changes[^<]*)<\/button>/.exec(html)?.[0] ?? '';
    expect(saveButton).not.toBe('');
    expect(saveButton).not.toContain('disabled=""');
  });
});

// The history-sync equivalent, and the reason it exists is a defect the vault
// row never had: `initialHistorySync` used to be VALIDITY-derived, so a payload
// bump rendered a real grant as 'Not shared' with the form clean. Nothing was
// visibly wrong — and the next unrelated save submitted `historySyncConsent:
// false`, which the server action maps to `undefined` and DELETES, taking
// acknowledgedAt with it. The user was never asked; the grant simply vanished.
// The v2 payload, asserted against the copy that describes it. The schema's
// tripwire (packages/schema, "the payload version and its disclosure move
// together") fails on a bump and names this file; these are the claims it sends
// the author here to check. Substance, never headings — the whole failure mode
// is copy that still reads plausibly while describing a narrower payload.
describe('history-sync disclosure states what payload v2 sends', () => {
  it('names the captured text, the masking, and what declining costs', () => {
    // The widening: captured text is inside the grant now.
    expect(HISTORY_SYNC_SECTION_DESCRIPTION).toContain('INCLUDES ITS TEXT');
    // ...and it is not raw — the masking is part of the claim.
    expect(HISTORY_SYNC_SECTION_DESCRIPTION).toContain('masked');
    // Declining must not be sold as "this stops sending"; live sending remains.
    expect(HISTORY_SYNC_SECTION_DESCRIPTION).toContain('Live sending is part of being attached');
    expect(HISTORY_SYNC_SECTION_DESCRIPTION).toContain('dropped rather than kept');
    // The pre-attach half of the grant did not go away when v2 widened it.
    expect(HISTORY_SYNC_SECTION_DESCRIPTION).toContain('before it attached');
  });

  it('does not still claim prompts and replies are never sent', () => {
    // The exact v1 sentence, which v2 makes false. A guard on the NEW wording
    // alone would pass with this left sitting beside it.
    const all = [
      HISTORY_SYNC_SECTION_DESCRIPTION,
      ...HISTORY_SYNC_CHOICES.map((c) => c.description),
    ].join(' ');
    expect(all).not.toContain('never the prompts or replies themselves');
    expect(all).not.toContain('Prompts and assistant replies are not sent');
  });

  it('offers the paused grant a way back that names what changed', () => {
    expect(HISTORY_SYNC_STALE_NOTICE).toContain('older version');
    expect(HISTORY_SYNC_STALE_NOTICE).toContain('re-consent');
  });
});

describe('stale history-sync grant', () => {
  const ENDPOINT = 'https://plane.example.com';
  const attached = (consent: WorkspaceSettings['historySyncConsent']): WorkspaceSettings => ({
    specVersion: 6,
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: '2020-01-01T00:00:00.000Z' },
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    historySyncConsent: consent,
  });

  const render = (settings: WorkspaceSettings): string =>
    renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, { settings, onSave: () => undefined, busy: false }),
    );

  it('shows the paused badge and an opened row, and does NOT pre-assert consent', () => {
    const html = render(
      attached({
        acknowledgedAt: '2020-01-01T00:00:00.000Z',
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1,
        endpoint: ENDPOINT,
      }),
    );
    expect(html).toContain('data-slot="history-sync-stale-notice"');
    // Same collapsed-<details> trap as the vault case: rendered is not visible.
    const staleRow = html.slice(0, html.indexOf('data-slot="history-sync-stale-notice"'));
    const rowOpen = staleRow.lastIndexOf('<details');
    expect(staleRow.slice(rowOpen, staleRow.indexOf('>', rowOpen) + 1)).toContain('open');
    expect(html).toContain(HISTORY_SYNC_STALE_BADGE);
    // THE FAIL-OPEN GUARD. The submit handler asserts whatever this row is
    // seeded with, so a stale grant seeded 'Shared' would let a user who came to
    // change something else stamp a fresh v2 grant by clicking Save — silently
    // re-consenting to a widened payload. It must read 'Not shared' until the
    // user says otherwise; the badge and notice are what explain why.
    // Anchored on the choice COPY, because the radios carry no value attribute —
    // selection is `checked` on the label that holds the description.
    const grantedCopy = HISTORY_SYNC_CHOICES.find((c) => c.value === 'granted')?.description ?? '';
    const revokedCopy = HISTORY_SYNC_CHOICES.find((c) => c.value === 'revoked')?.description ?? '';
    expect(grantedCopy).not.toBe('');
    const labelHolding = (copy: string): string => {
      const at = html.indexOf(copy);
      return html.slice(html.lastIndexOf('<label', at), at);
    };
    expect(labelHolding(grantedCopy)).not.toContain('checked');
    expect(labelHolding(revokedCopy)).toContain('checked');
    // And the form starts clean, so an untouched Save is not even offered.
    const saveButton = /<button[^>]*>(?:[^<]*Save changes[^<]*)<\/button>/.exec(html)?.[0] ?? '';
    expect(saveButton).toContain('disabled=""');
  });

  // THE SAFETY CASE, which the vault row has no analogue for because a vault
  // grant names no deployment. A grant given to ANOTHER endpoint must read as
  // no grant: no paused badge, and a clean form, so that no single save can
  // quietly re-point this machine's activity at a deployment the user never
  // chose. If this regresses, the bug is invisible — the row just looks helpful.
  it('does not offer a re-consent for a grant naming a different deployment', () => {
    const html = render(
      attached({
        acknowledgedAt: '2020-01-01T00:00:00.000Z',
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1,
        endpoint: 'https://someone-else.example.com',
      }),
    );
    expect(html).not.toContain('data-slot="history-sync-stale-notice"');
    expect(html).not.toContain(HISTORY_SYNC_STALE_BADGE);
    const saveButton = /<button[^>]*>(?:[^<]*Save changes[^<]*)<\/button>/.exec(html)?.[0] ?? '';
    expect(saveButton).toContain('disabled=""');
  });

  // A current grant is not paused; the row is an ordinary "Shared".
  it('shows no paused badge for a grant covering the current payload', () => {
    const html = render(
      attached({
        acknowledgedAt: '2020-01-01T00:00:00.000Z',
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: ENDPOINT,
      }),
    );
    expect(html).not.toContain('data-slot="history-sync-stale-notice"');
    expect(html).not.toContain(HISTORY_SYNC_STALE_BADGE);
  });
});

// The Connection section and the administrative-lock affordance. Neither had any
// render coverage, and both are places where the rendered state IS the claim:
// a locked control that only looks disabled, or an attached machine described as
// exchanging data it never exchanges, is a lie the type system cannot catch.
describe('the connection section', () => {
  const base: WorkspaceSettings = {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };

  const attached: WorkspaceSettings = {
    ...base,
    runMode: 'attached',
    controlPlane: {
      endpoint: 'https://aka.acme.internal',
      label: 'Acme Prod',
      attachedAt: '2026-02-02T00:00:00.000Z',
    },
  };

  const render = (props: Partial<Parameters<typeof WorkspaceSettingsFormView>[0]> = {}): string =>
    renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, {
        settings: base,
        onSave: () => undefined,
        ...props,
      }),
    );

  it('offers an attach form and no detach when standalone', () => {
    const html = render({ onAttach: () => undefined, onDetach: () => undefined });
    expect(html).toContain('data-slot="attach-form"');
    expect(html).not.toContain('data-slot="detach-button"');
    expect(html).toContain(CONNECTION_STANDALONE_DESCRIPTION);
  });

  it('offers a masked access-key field, and says where the key comes from', () => {
    const html = render({ onAttach: () => undefined, onDetach: () => undefined });

    // Masked, and opted out of the three browser features that would defeat
    // the masking by another route: a saved password, a spellchecker shipping
    // the value to a remote dictionary, and autocorrect rewriting it.
    //
    // Matched case-INSENSITIVELY. This renderer serialises these three as
    // `autoComplete` / `spellCheck` / `autoCorrect` rather than lowercasing
    // them; HTML attribute names are case-insensitive so a browser honours
    // them either way, and pinning the casing would fail on a renderer change
    // that broke nothing.
    expect(html).toContain('type="password"');
    expect(html).toContain('aria-label="Access key"');
    // `new-password`, not `off`: on a password field the browsers deliberately
    // DISREGARD `off`, so password managers keep working on sites that set it.
    // Asserting `off` would have been green while the property it stands for —
    // no autofill, no save prompt — was not obtained.
    expect(html).toMatch(/autocomplete="new-password"/i);
    expect(html).toMatch(/spellcheck="false"/i);
    expect(html).toMatch(/autocorrect="off"/i);
    // The kind is named because it is the one attach failure a user cannot
    // diagnose from the outside: an ingest key authenticates, then fails.
    expect(html).toContain(ATTACH_KEY_HINT);
  });

  it('clears the key BEFORE handing the attach off, not after it resolves', () => {
    // The ordering is the security property. The attach is async and the form
    // stays mounted across it, so clearing afterwards would leave the secret in
    // a live input for the whole round trip — including the failure case, where
    // the form stays on screen with the key still in it.
    const order: string[] = [];
    const clearKey = () => order.push('cleared');
    const onAttach = (...args: string[]) => order.push(`sent:${args.join('|')}`);

    submitAttach(
      { endpoint: '  https://aka.acme.internal ', label: ' Acme ', accessKey: '  aka_live_k  ' },
      clearKey,
      onAttach,
    );

    // Cleared first, and the trimmed key still reached the handler — the clear
    // must not race the value it is handing over.
    expect(order).toEqual(['cleared', 'sent:https://aka.acme.internal|Acme|aka_live_k']);
  });

  it('requires both halves of an attachment, whitespace not counting', () => {
    // The rule the button's disabled state enforces, tested where it can be
    // reached. An endpoint with no key is the case that matters: it writes a
    // descriptor with no credential, which every later surface reads as
    // attached-and-broken.
    expect(canAttach('https://aka.acme.internal', 'aka_live_k')).toBe(true);
    expect(canAttach('https://aka.acme.internal', '')).toBe(false);
    expect(canAttach('https://aka.acme.internal', '   ')).toBe(false);
    expect(canAttach('', 'aka_live_k')).toBe(false);
    expect(canAttach('   ', 'aka_live_k')).toBe(false);
    expect(canAttach('  https://aka.acme.internal  ', '  aka_live_k  ')).toBe(true);
  });

  it('ships the attach button disabled, with both fields empty', () => {
    // WHAT THIS DOES NOT COVER, said plainly because the title used to claim it:
    // that the button's `disabled` consults `canAttach`. ConnectionRow holds the
    // two fields in its own state with no way to seed them, so the only case
    // that renders has both empty — and swapping the condition back to
    // `endpoint.trim() === ''` leaves this green. The RULE is covered by
    // canAttach's own unit test above; the WIRE between them is not, and
    // pretending otherwise is worse than the gap.
    const html = render({ onAttach: () => undefined, onDetach: () => undefined });
    const at = html.indexOf('data-slot="attach-button"');
    expect(at).toBeGreaterThan(-1);
    expect(html.slice(Math.max(0, at - 400), at)).toContain('disabled');
  });

  it('offers a detach and names the deployment when attached', () => {
    const html = render({
      settings: attached,
      onAttach: () => undefined,
      onDetach: () => undefined,
    });
    expect(html).toContain('data-slot="detach-button"');
    expect(html).not.toContain('data-slot="attach-form"');
    // The label, not the raw endpoint, when one was supplied.
    expect(html).toContain('Acme Prod');
  });

  it('says plainly that the plugin forwards, on an attached machine', () => {
    // The honesty requirement, and it inverted when attached mode shipped. This
    // notice used to say the build carried no transport and sent nothing; it
    // renders on `attached &&` with no capability check, so it went on saying so
    // after the transport landed. An attached machine must be told it sends.
    expect(
      render({ settings: attached, onAttach: () => undefined, onDetach: () => undefined }),
    ).toContain('data-slot="connection-forwarding"');
  });

  it('states the unavailable notice when no attach handler is supplied', () => {
    // A surface that cannot attach says so rather than rendering a form whose
    // button does nothing.
    const html = renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, { settings: base, onSave: () => undefined }),
    );
    // With no onAttach the form is replaced by the notice.
    expect(html).toContain('data-slot="connection-unavailable"');
    expect(html).toContain(CONNECTION_UNAVAILABLE_NOTICE);
  });

  it('does not render the detach explanation when there is no detach button', () => {
    // The explanation describes a button. Rendered without one it reads as a
    // rendering fault rather than as this surface deliberately offering no exit.
    const html = render({ settings: attached, onAttach: () => undefined });
    expect(html).not.toContain('data-slot="detach-button"');
    expect(html).not.toContain(DETACH_EXPLANATION);
    expect(html).toContain('data-slot="detach-unavailable"');
  });

  it('pairs the explanation WITH the button when detach is available', () => {
    // The positive control for the case above.
    const html = render({
      settings: attached,
      onAttach: () => undefined,
      onDetach: () => undefined,
    });
    expect(html).toContain('data-slot="detach-button"');
    expect(html).toContain(DETACH_EXPLANATION);
    expect(html).not.toContain('data-slot="detach-unavailable"');
  });

  it('withholds detach and explains why when the connection is managed', () => {
    const html = render({
      settings: attached,
      onAttach: () => undefined,
      onDetach: () => undefined,
      managed: { present: true, organization: 'Acme', lockedFields: ['runMode'] },
    });
    expect(html).not.toContain('data-slot="detach-button"');
    expect(html).toContain('data-slot="connection-managed-notice"');
    expect(html).toContain('Acme');
    expect(html).toContain(DETACH_MANAGED_NOTICE);
  });
});

// React server-renders attributes in its own order — `disabled` lands BEFORE
// `name` — so an assertion that slices forward from the name attribute silently
// misses it and reports a working lock as broken. Read the whole element.
function inputFor(html: string, name: string): string {
  const at = html.indexOf(`name="${name}"`);
  if (at === -1) throw new Error(`no input named ${name} in the rendered form`);
  const open = html.lastIndexOf('<input', at);
  const close = html.indexOf('>', at);
  return html.slice(open, close + 1);
}

describe('administratively locked rows', () => {
  const settings: WorkspaceSettings = {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'full',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };

  const lockedHtml = (): string =>
    renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, {
        settings,
        onSave: () => undefined,
        managed: { present: true, organization: 'Acme', lockedFields: ['historicalAccess'] },
      }),
    );

  it('actually DISABLES the inputs, not merely dims them', () => {
    // The property that matters: a row that only looked disabled would still be
    // reachable by keyboard and would still post a value the writer refuses.
    expect(inputFor(lockedHtml(), 'historicalAccess')).toContain('disabled');
  });

  it('says who decided, so a locked control is not read as a bug', () => {
    const html = lockedHtml();
    expect(html).toContain('data-slot="managed-notice"');
    expect(html).toContain('Acme');
  });

  it('leaves an UNLOCKED row editable on the same managed machine', () => {
    // Per-field locking is the whole point; an all-or-nothing lock would make
    // the managed layer far blunter than it claims to be.
    expect(inputFor(lockedHtml(), 'vaultInlineReveal')).not.toContain('disabled');
  });

  it('renders every row editable when nothing is managed', () => {
    // The positive control: without it, a form that disabled everything would
    // satisfy the disabled-check above.
    const html = renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, { settings, onSave: () => undefined }),
    );
    expect(inputFor(html, 'historicalAccess')).not.toContain('disabled');
    expect(html).not.toContain('data-slot="managed-notice"');
  });
});

describe('the enforcement pointer', () => {
  const settings: WorkspaceSettings = {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };

  it('links to the Detections page and offers no control of its own', () => {
    const html = renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, { settings, onSave: () => undefined }),
    );
    expect(html).toContain('data-slot="enforcement-pointer"');
    expect(html).toContain('href="/detections"');
    expect(html).toContain(HANDLING_SECTION_LINK_LABEL);
    // No radio group for handling — that is the whole point of the section.
    expect(html).not.toContain('name="policy"');
  });

  it('honours an injected href so the package stays router-agnostic', () => {
    const html = renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, {
        settings,
        onSave: () => undefined,
        detectionsHref: '/app/detections',
      }),
    );
    expect(html).toContain('href="/app/detections"');
  });
});

// ─── The credential half of an attachment ────────────────────────────────────
//
// `runMode: 'attached'` is only half of a working attachment. The other half is
// a usable credential file, and when it is missing or was minted for a
// different deployment the machine sends and receives nothing while every
// surface still says "Attached". `aka status` has always been able to say so;
// this view could not, because it renders from `WorkspaceSettings` alone.
//
// What makes this honest to show — where a live handshake would not be — is
// that the credential is a LOCAL fact. The page is not claiming anything about
// whether the deployment answered; it is reporting what is on this disk.
describe('the connection section, credential state', () => {
  const base: WorkspaceSettings = {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };

  const attached: WorkspaceSettings = {
    ...base,
    runMode: 'attached',
    controlPlane: {
      endpoint: 'https://aka.acme.internal',
      label: 'Acme Prod',
      attachedAt: '2026-02-02T00:00:00.000Z',
    },
  };

  const render = (props: Partial<WorkspaceSettingsFormViewProps> = {}): string =>
    renderToStaticMarkup(
      createElement(WorkspaceSettingsFormView, {
        settings: attached,
        onSave: () => undefined,
        ...props,
      }),
    );

  // A VERDICT AND NOTHING ELSE, which is the whole of the usable branch. This
  // package is presentational and its props are handed across a client boundary
  // by at least one host, so the type it takes cannot carry a credential — and
  // the view has never read one: `credentialNotice` branches on `usable` and
  // `reason`.
  const usable: CredentialState = { usable: true };

  it('says nothing extra when the credential is usable', () => {
    const html = render({ credentialState: usable });
    expect(html).not.toContain('data-slot="connection-credential-notice"');
    expect(html).toContain(CONNECTION_ATTACHED_LABEL);
    expect(html).not.toContain(CONNECTION_INACTIVE_BADGE);
  });

  // The host may not supply the state at all — the CLI inlines this package and
  // renders the same view. An absent prop must leave the surface exactly as it
  // was rather than accusing a working machine of being broken.
  it('says nothing extra when the host supplies no credential state', () => {
    const html = render();
    expect(html).not.toContain('data-slot="connection-credential-notice"');
    expect(html).toContain(CONNECTION_ATTACHED_LABEL);
  });

  it('names a missing credential, and stops calling the machine attached', () => {
    const html = render({ credentialState: { usable: false, reason: 'absent' } });
    expect(html).toContain(CONNECTION_CREDENTIAL_MISSING_NOTICE);
    expect(html).toContain(CONNECTION_INACTIVE_BADGE);
  });

  // Four different reasons, one message. A user cannot act differently on
  // "malformed" than on "unreadable" — the fix is the same in every case — and
  // naming the internal distinction would be describing our parser rather than
  // their machine.
  it.each(['untrusted-file', 'unreadable', 'malformed', 'unsafe-endpoint'] as const)(
    'reports a %s credential as unusable',
    (reason) => {
      const html = render({ credentialState: { usable: false, reason } });
      expect(html).toContain(CONNECTION_CREDENTIAL_UNUSABLE_NOTICE);
      expect(html).toContain(CONNECTION_INACTIVE_BADGE);
    },
  );

  // The one reason that carries data, and the only one a user can act on in two
  // different directions — so both endpoints have to be on screen or the advice
  // is unfollowable.
  it('names both endpoints on a mismatch', () => {
    const html = render({
      credentialState: {
        usable: false,
        reason: 'endpoint-mismatch',
        credentialEndpoint: 'https://old.acme.internal',
        settingsEndpoint: 'https://aka.acme.internal',
      },
    });
    expect(html).toContain('https://old.acme.internal');
    expect(html).toContain('https://aka.acme.internal');
    expect(html).toContain(CONNECTION_INACTIVE_BADGE);
  });

  // A standalone machine is not "missing" a credential — it is not supposed to
  // have one. Reporting absence there would turn the ordinary state into a
  // fault.
  it('reports nothing on a standalone machine', () => {
    const html = render({ settings: base, credentialState: { usable: false, reason: 'absent' } });
    expect(html).not.toContain('data-slot="connection-credential-notice"');
    expect(html).not.toContain(CONNECTION_INACTIVE_BADGE);
  });
});
