import type { HistorySyncConsent, WorkspaceSettings } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import {
  HISTORY_SYNC_CHOICES,
  HISTORY_SYNC_CHOICES_SCOPED,
  HISTORY_SYNC_ROW_DESCRIPTION,
  HISTORY_SYNC_ROW_DESCRIPTION_SCOPED,
  HISTORY_SYNC_SECTION_DESCRIPTION,
  HISTORY_SYNC_SECTION_DESCRIPTION_SCOPED,
  HISTORY_SYNC_STALE_NOTICE,
  HISTORY_SYNC_STALE_NOTICE_SCOPED,
  WorkspaceSettingsFormView,
  type WorkspaceSettingsFormViewProps,
} from '../../src/settings/WorkspaceSettingsFormView.tsx';

// The Unsent activity row on a machine attached as a personal device. Such a
// machine sends activity only from its enrolled repositories, so every string
// the row shows there names them and none describes the whole machine's backlog.
// The host passes the credential's mode as `attachmentMode`; anything but
// 'scoped' keeps the machine-wide wording, the one that says more is sent,
// never less.

const ENDPOINT = 'https://plane.example.com';

function attached(consent: HistorySyncConsent): WorkspaceSettings {
  return {
    specVersion: 6,
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: '2020-01-01T00:00:00.000Z' },
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
    historySyncConsent: consent,
  };
}

const CURRENT: HistorySyncConsent = {
  acknowledgedAt: '2020-01-01T00:00:00.000Z',
  payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
  endpoint: ENDPOINT,
};
// A grant against the previous payload: the row then renders its summary, its
// disclosure, both choices AND the paused notice, so one render shows every
// string the row has.
const STALE: HistorySyncConsent = { ...CURRENT, payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 };

function render(
  settings: WorkspaceSettings,
  mode?: WorkspaceSettingsFormViewProps['attachmentMode'],
): string {
  return renderToStaticMarkup(
    createElement(WorkspaceSettingsFormView, {
      settings,
      onSave: () => undefined,
      busy: false,
      ...(mode === undefined ? {} : { attachmentMode: mode }),
    }),
  );
}

// The markup escapes text, so a string is looked for as the renderer emits it.
function asHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

const scopedStrings = (): string[] => [
  HISTORY_SYNC_ROW_DESCRIPTION_SCOPED,
  HISTORY_SYNC_SECTION_DESCRIPTION_SCOPED,
  ...HISTORY_SYNC_CHOICES_SCOPED.map((c) => c.description),
  HISTORY_SYNC_STALE_NOTICE_SCOPED,
];

const machineStrings = (): string[] => [
  HISTORY_SYNC_ROW_DESCRIPTION,
  HISTORY_SYNC_SECTION_DESCRIPTION,
  ...HISTORY_SYNC_CHOICES.map((c) => c.description),
  HISTORY_SYNC_STALE_NOTICE,
];

describe('history-sync copy on a personal device', () => {
  // Frozen literals of the machine-wide wording, copied out of the source as it
  // stood before personal devices had their own. A change to any of them fails
  // here rather than travelling with the constant.
  it('keeps the machine-wide wording exactly as it was', () => {
    expect(HISTORY_SYNC_SECTION_DESCRIPTION).toBe(
      'Whether activity this machine has not delivered to the deployment it is attached to may be ' +
        'sent later. Two kinds qualify: what was already recorded before it attached, and anything a ' +
        'live send could not deliver because the deployment was unreachable or refused the ' +
        'credential. Both are sent the same way: which sessions ran and when, in which project, repo ' +
        'and branch, token usage and model per call, which tools were called with their inputs ' +
        'truncated and every detected secret already masked, what was detected in those inputs, and ' +
        'the prompts, assistant replies and tool results themselves — for which a captured one ' +
        'INCLUDES ITS TEXT. What is masked in that text follows the policy assigned to ' +
        'the detection that flagged the value: it is masked only where that policy is redact or ' +
        'block, and under monitor or warn the value is sent as it was seen, as is everything outside ' +
        'a flagged span. No detection ships on redact or block, so on a default install nothing in that ' +
        'text is masked. Live sending is part of being attached and this setting does not change ' +
        'it: declining means an undelivered item is dropped rather than kept and retried. Sending ' +
        'happens in the background over later sessions. Revoking stops what has not been sent; it ' +
        'cannot recall what has.',
    );
    expect(HISTORY_SYNC_CHOICES).toEqual([
      {
        value: 'revoked',
        label: 'Not shared',
        description:
          'Anything not delivered live is dropped, as it was before this setting existed (default — never assumed).',
      },
      {
        value: 'granted',
        label: 'Shared',
        description:
          'Activity from before this machine attached, and anything undelivered since, may be sent later — including the text of prompts, replies and tool results, in which a value is masked only where the detection that flagged it is set to redact or block.',
      },
    ]);
    expect(HISTORY_SYNC_STALE_NOTICE).toBe(
      'Your grant was recorded against an older version of this setting, which did not cover the ' +
        'text of the activity recorded before this machine attached — only what a live send failed ' +
        'to deliver afterward — sending is paused until you re-consent. Saving with "Shared" ' +
        'selected re-consents to the current version.',
    );
    // The row's one-line summary was written inline in the row; the rendered
    // text is what has to stay.
    expect(render(attached(CURRENT))).toContain(
      'Whether activity this machine has not delivered may be sent later.',
    );
  });

  it('names the inline summary exactly as the row showed it', () => {
    expect(HISTORY_SYNC_ROW_DESCRIPTION).toBe(
      'Whether activity this machine has not delivered may be sent later.',
    );
  });

  it('renders the personal-device wording on a scoped attachment, and none of the machine-wide', () => {
    const html = render(attached(STALE), 'scoped');
    expect(html).toContain('data-slot="history-sync-stale-notice"');
    for (const text of scopedStrings()) expect(html).toContain(asHtml(text));
    for (const text of machineStrings()) expect(html).not.toContain(asHtml(text));
    // The whole-machine phrasing, wherever on the page it might come from.
    expect(html).not.toContain('activity this machine has not delivered');
    expect(html).not.toContain('before this machine attached');
    expect(html).not.toContain('before it attached');
  });

  it.each(['machine', undefined] as const)(
    'keeps the machine-wide wording when the reported mode is %s',
    (mode) => {
      const html = render(attached(STALE), mode);
      for (const text of machineStrings()) expect(html).toContain(asHtml(text));
      for (const text of scopedStrings()) expect(html).not.toContain(asHtml(text));
    },
  );

  // The fail-open guard the machine-wide row carries (see the stale-grant case
  // in WorkspaceSettingsFormView.test.ts): a paused grant must read "Not
  // shared", or an unrelated Save re-consents to a widened payload. Swapping
  // the choice set must not change which one is seeded.
  it('seeds a paused grant as not shared on a personal device too', () => {
    const html = render(attached(STALE), 'scoped');
    const shared =
      HISTORY_SYNC_CHOICES_SCOPED.find((c) => c.value === 'granted')?.description ?? '';
    const notShared =
      HISTORY_SYNC_CHOICES_SCOPED.find((c) => c.value === 'revoked')?.description ?? '';
    const labelHolding = (copy: string): string => {
      const at = html.indexOf(asHtml(copy));
      expect(at).toBeGreaterThan(-1);
      return html.slice(html.lastIndexOf('<label', at), at);
    };
    expect(labelHolding(shared)).not.toContain('checked');
    expect(labelHolding(notShared)).toContain('checked');
  });

  it('names the enrolled repositories in every string, and never the whole machine', () => {
    for (const text of scopedStrings()) {
      expect(text).toMatch(/enroll/);
      expect(text).not.toMatch(/this machine/i);
      expect(text).not.toContain('before it attached');
    }
    expect(HISTORY_SYNC_SECTION_DESCRIPTION_SCOPED).toContain(
      'Activity in any other repository, or outside one, is not sent.',
    );
    expect(HISTORY_SYNC_SECTION_DESCRIPTION_SCOPED).toContain(
      'With no repository enrolled, no activity is sent.',
    );
  });

  // Only the subject narrows. The payload, the masking rule and what declining
  // costs are the machine-wide disclosure's own claims, and a personal device's
  // reader is owed every one of them.
  it('carries the payload claims the machine-wide disclosure carries', () => {
    for (const claim of [
      'INCLUDES ITS TEXT',
      'masked only where that policy is redact',
      'under monitor or warn',
      'No detection ships on redact or block',
      'part of being attached',
      'dropped rather than kept',
      'cannot recall what has',
    ]) {
      expect(HISTORY_SYNC_SECTION_DESCRIPTION_SCOPED).toContain(claim);
    }
    const shared = HISTORY_SYNC_CHOICES_SCOPED.find((c) => c.value === 'granted');
    expect(shared?.description).toContain(
      'masked only where the detection that flagged it is set to redact or block',
    );
    expect(HISTORY_SYNC_STALE_NOTICE_SCOPED).toContain('older version');
    expect(HISTORY_SYNC_STALE_NOTICE_SCOPED).toContain('re-consent');
  });

  // Sentences the machine-wide copy once carried and had to drop, each made
  // false by a widening of what is sent. The machine-wide pins sweep only the
  // machine-wide strings, so the personal-device twins are swept here.
  it('does not carry back a sentence the machine-wide copy retired', () => {
    const all = scopedStrings().join(' ');
    for (const retired of [
      'never the prompts or replies themselves',
      'Prompts and assistant replies are not sent',
      'the record of activity only',
      'every secret this machine detected is masked first',
      'with detected secrets masked',
    ]) {
      expect(all).not.toContain(retired);
    }
  });

  // The paused notice tells the reader which answer to save, by its label.
  it('offers the same two answers under the same names', () => {
    expect(HISTORY_SYNC_CHOICES_SCOPED.map((c) => [c.value, c.label])).toEqual(
      HISTORY_SYNC_CHOICES.map((c) => [c.value, c.label]),
    );
    expect(HISTORY_SYNC_STALE_NOTICE_SCOPED).toContain('Saving with "Shared" selected');
  });
});
