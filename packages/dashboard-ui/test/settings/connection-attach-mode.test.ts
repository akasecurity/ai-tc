import type { WorkspaceSettings } from '@akasecurity/schema';
import { AttachmentMode } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import {
  ATTACH_MODE_CHOICES,
  ATTACH_MODE_LABEL,
  ATTACH_MODE_MANAGED_NOTICE,
  attachFormMode,
  CONNECTION_FORWARDING_NOTICE,
  CONNECTION_FORWARDING_NOTICE_SCOPED,
  CONNECTION_MODE_MACHINE,
  CONNECTION_MODE_SCOPED,
  submitAttach,
  WorkspaceSettingsFormView,
  type WorkspaceSettingsFormViewProps,
} from '../../src/settings/WorkspaceSettingsFormView.tsx';

// The attachment mode on the connection section: the choice the attach form
// offers, the line an attached row shows, and the forwarding notice a scoped
// machine gets instead of the machine-wide one. Copy on this section is a
// consent surface, so each string is held to what a scoped machine actually
// sends: activity from enrolled repositories, the policy pull and a short report
// on the install, and nothing else.

// The phrasings WorkspaceSettingsFormView.test.ts bans on every section, repeated
// for the strings this file adds (that list is not exported; see its note).
const ALWAYS_FALSE = [/next hook/i, /nothing is altered/i, /immediately/i, /right away/i];

const NEW_COPY: Record<string, string> = {
  ATTACH_MODE_LABEL,
  ATTACH_MODE_MANAGED_NOTICE,
  CONNECTION_FORWARDING_NOTICE_SCOPED,
  CONNECTION_MODE_MACHINE,
  CONNECTION_MODE_SCOPED,
  ...Object.fromEntries(
    ATTACH_MODE_CHOICES.flatMap((c) => [
      [`ATTACH_MODE_CHOICES.${c.value}.label`, c.label],
      [`ATTACH_MODE_CHOICES.${c.value}.description`, c.description],
    ]),
  ),
};

const ENDPOINT = 'https://aka.example.com';

const standalone: WorkspaceSettings = {
  specVersion: 1,
  runMode: 'standalone',
  policy: 'redact',
  historicalAccess: 'session-only',
  dataSharesInPlace: true,
  vaultKeyCustody: 'file',
  vaultInlineReveal: 'masked',
  redactFallback: 'warn',
  bodyRetention: { enabled: false, retainDays: 30 },
};

const attached: WorkspaceSettings = {
  ...standalone,
  runMode: 'attached',
  controlPlane: { endpoint: ENDPOINT, label: 'Acme Prod', attachedAt: '2026-10-01T00:00:00.000Z' },
};

const render = (props: Partial<WorkspaceSettingsFormViewProps> = {}): string =>
  renderToStaticMarkup(
    createElement(WorkspaceSettingsFormView, {
      settings: standalone,
      onSave: () => undefined,
      ...props,
    }),
  );

/** The markup between the mode group and the key hint that follows it. */
function modeGroup(html: string): string {
  const start = html.indexOf('data-slot="attach-mode"');
  const end = html.indexOf('data-slot="attach-key-hint"');
  if (start === -1 || end === -1) throw new Error('the attach form has no mode group');
  return html.slice(start, end);
}

describe('attach-mode copy', () => {
  it.each(Object.entries(NEW_COPY))('%s claims no live, altering effect', (_name, text) => {
    for (const claim of ALWAYS_FALSE) expect(text).not.toMatch(claim);
  });

  it('offers exactly the two modes a credential can record', () => {
    expect(ATTACH_MODE_CHOICES.map((c) => c.value).sort()).toEqual(
      [...AttachmentMode.options].sort(),
    );
  });

  it('names the enroll verb on the personal-device choice and says the rest stays here', () => {
    const scoped = ATTACH_MODE_CHOICES.find((c) => c.value === 'scoped');
    expect(scoped?.description).toMatch(/aka enroll/);
    expect(scoped?.description).toMatch(/stays on this machine/i);
  });

  it('words the personal-device choice and mode line so they cannot read as "nothing else is sent"', () => {
    // The install report goes in both modes, so "only activity ... is sent"
    // would claim less than is sent. The activity is what is limited.
    const scoped = ATTACH_MODE_CHOICES.find((c) => c.value === 'scoped');
    expect(scoped?.description).toMatch(/Activity is sent only from repositories you enroll/);
    expect(CONNECTION_MODE_SCOPED).toMatch(
      /Activity is sent only from repositories enrolled with `aka enroll`/,
    );
    expect(scoped?.description).not.toMatch(/Only activity/);
    expect(CONNECTION_MODE_SCOPED).not.toMatch(/Only activity/);
  });

  it('says on a governed machine that a personal-device attach is refused', () => {
    // There is no pick to offer: a scoped request is refused, and any other
    // attach is machine-wide.
    expect(ATTACH_MODE_MANAGED_NOTICE).toMatch(/personal-device attach is refused/i);
    expect(ATTACH_MODE_MANAGED_NOTICE).toMatch(/organization device/i);
    expect(ATTACH_MODE_MANAGED_NOTICE).not.toMatch(/whatever is picked/i);
  });

  it('says on a scoped machine what still goes, and what does not', () => {
    // A scoped machine still pulls policy and sends a report on the install —
    // both send without a scope verdict, by design — so a notice that said
    // "nothing else is sent" would be false.
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/plugin forwards activity only from/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/aka enroll/);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/stays on this machine/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/policy/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/host name/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/finding counts/i);
    // The report is introduced as including these, not as consisting of them:
    // it also carries a device identifier, policy counts and the dates of the
    // first and latest finding, and the machine checks for device commands.
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/report on this install that includes/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/device identifier/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/policy counts/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/first and latest finding/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/checks for commands/i);
    // The Scan page's register goes only for an enrolled repository, and the
    // notice must not read as if every scan sends one.
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(
      /Data Shares register only for an enrolled repository/i,
    );
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/never source text/i);
    // An older build re-attaching writes a machine-wide credential.
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/older than this one/i);
  });
});

describe('the attach form', () => {
  it('offers the mode with nothing chosen', () => {
    const html = render({ onAttach: () => undefined });
    const group = modeGroup(html);
    expect(group).toContain(ATTACH_MODE_LABEL);
    for (const choice of ATTACH_MODE_CHOICES) expect(group).toContain(choice.label);
    // No default: a first attach is a decision, not a pre-ticked box.
    expect(group).not.toContain('checked');
  });

  it('offers no choice on a machine held to machine-wide, and says so', () => {
    const html = render({ onAttach: () => undefined, machineOnly: true });
    expect(html).not.toContain('data-slot="attach-mode"');
    expect(html).toContain('data-slot="attach-mode-managed"');
    expect(html).toContain(ATTACH_MODE_MANAGED_NOTICE);
  });
});

describe('an attached machine', () => {
  it('names a scoped attachment and gives it the scoped notice', () => {
    const html = render({
      settings: attached,
      onDetach: () => undefined,
      attachmentMode: 'scoped',
    });
    expect(html).toContain('data-slot="connection-mode"');
    expect(html).toContain(CONNECTION_MODE_SCOPED);
    expect(html).toContain(CONNECTION_FORWARDING_NOTICE_SCOPED);
    expect(html).not.toContain(CONNECTION_FORWARDING_NOTICE);
  });

  it('names a machine-wide attachment and keeps the machine-wide notice', () => {
    const html = render({
      settings: attached,
      onDetach: () => undefined,
      attachmentMode: 'machine',
    });
    expect(html).toContain(CONNECTION_MODE_MACHINE);
    expect(html).toContain(CONNECTION_FORWARDING_NOTICE);
    expect(html).not.toContain(CONNECTION_FORWARDING_NOTICE_SCOPED);
  });

  it('names no mode when the host reports none, and describes the wider case', () => {
    // Absent means "not reported". The machine-wide notice claims MORE is sent,
    // never less, so it is the one a row that cannot tell renders.
    const html = render({ settings: attached, onDetach: () => undefined });
    expect(html).not.toContain('data-slot="connection-mode"');
    expect(html).toContain(CONNECTION_FORWARDING_NOTICE);
  });
});

describe('attachFormMode', () => {
  it('takes the choice the user made over anything kept', () => {
    expect(attachFormMode('machine', ENDPOINT, ENDPOINT, 'scoped')).toBe('machine');
  });

  it('defaults to the kept mode only for the endpoint the settings name, typed with spaces', () => {
    expect(attachFormMode(null, `  ${ENDPOINT} `, ENDPOINT, 'scoped')).toBe('scoped');
    expect(attachFormMode(null, 'https://other.example.com', ENDPOINT, 'scoped')).toBeNull();
  });

  it('has no default with nothing kept', () => {
    expect(attachFormMode(null, ENDPOINT, undefined, undefined)).toBeNull();
    expect(attachFormMode(null, ENDPOINT, ENDPOINT, undefined)).toBeNull();
  });
});

describe('submitAttach and the mode', () => {
  it('clears the key first, then hands the chosen mode over as the fourth argument', () => {
    const order: string[] = [];
    submitAttach(
      { endpoint: ` ${ENDPOINT} `, label: '', accessKey: ' test-key ', mode: 'scoped' },
      () => order.push('cleared'),
      (...args) => order.push(`sent:${args.join('|')}`),
    );
    expect(order).toEqual(['cleared', `sent:${ENDPOINT}||test-key|scoped`]);
  });

  it('hands over no mode at all when the form carries none', () => {
    const lengths: number[] = [];
    submitAttach(
      { endpoint: ENDPOINT, label: '', accessKey: 'test-key', mode: undefined },
      () => undefined,
      (...args) => lengths.push(args.length),
    );
    expect(lengths).toEqual([3]);
  });
});
