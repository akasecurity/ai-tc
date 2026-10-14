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
// sends: activity only from enrolled repositories, and whenever a session starts
// anywhere on the machine the policy pull and a device report whose finding counts
// and dates are for everything recorded on it, which on a personal device also says
// that it is one, plus the check for device commands where a scan is available.
// The strings say that these happen, in the terms the terminal command uses, and
// none of them says "nothing else".

// The phrasings WorkspaceSettingsFormView.test.ts bans on every section, repeated
// for the strings this file adds (that list is not exported; see its note).
const ALWAYS_FALSE = [/next hook/i, /nothing is altered/i, /immediately/i, /right away/i];

// The sentence about what every attached machine sends, as the terminal command and
// the README word it. The two halves are pinned apart because only the owner of
// the policy differs: the choice, a question, says "your organization's", and the
// notices, a summary, say "that deployment's".
const SESSION_START =
  'Whenever a session starts anywhere on this machine, in a repository or not (a browser chat included), the machine pulls';
const POLICY_AND_REPORT =
  'policy (at most every 15 minutes) and sends it a device report (at most hourly): a device ' +
  'identifier, host name, versions, detection packs, policy counts, finding counts and dates ' +
  'for everything recorded on the machine, and, when the machine is attached as a personal ' +
  'device, the fact that it is one. Where a scan is available (the coding-agent plugins, not ' +
  'a browser chat), the same session start also checks it for device commands.';
// The second half as it stood before the report said whether the machine is a personal
// device. A string that kept it beside the new one would contradict itself.
const PREVIOUS_POLICY_AND_REPORT =
  'policy (at most every 15 minutes) and sends it a device report (at most hourly): a device ' +
  'identifier, host name, versions, detection packs, policy counts, and finding counts and ' +
  'dates for everything recorded on the machine. Where a scan is available (the coding-agent ' +
  'plugins, not a browser chat), the same session start also checks it for device commands.';

// What the strings used to say, and must not again: a count "across every
// repository" reads as a limit to repositories, and "every project" leaves out a
// session that belongs to none.
const OLD_WORDING = [
  /across every repositor/i,
  /every project/i,
  /all repositories/i,
  /whole machine/i,
  /nothing else/i,
];

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

/** Text as the server render writes it: the sentences carry apostrophes, which it escapes. */
const inMarkup = (text: string): string => text.replaceAll("'", '&#x27;');

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

  it.each(Object.entries({ ...NEW_COPY, CONNECTION_FORWARDING_NOTICE }))(
    '%s uses none of the wording it replaced',
    (_name, text) => {
      // The header above holds every string to what is sent. A session outside a
      // repository, or a browser chat, is sent too, so "every project" and "nothing
      // else" would be false of the machine-wide mode and of the report in the
      // scoped one, and a count "across every repository" reads as a limit.
      for (const old of OLD_WORDING) expect(text).not.toMatch(old);
    },
  );

  it('describes machine-wide as activity from anywhere on the machine', () => {
    // A session outside a git repository, or a browser chat, is sent in this mode
    // although it belongs to no project, so "every project" would claim less.
    const machine = ATTACH_MODE_CHOICES.find((c) => c.value === 'machine')?.description ?? '';
    for (const text of [machine, CONNECTION_MODE_MACHINE, ATTACH_MODE_MANAGED_NOTICE]) {
      expect(text).toMatch(/activity from anywhere on (this machine|it)/i);
      expect(text).not.toMatch(/every project/i);
    }
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

  it('names the device report on the personal-device choice, where the decision is made', () => {
    // The report goes in both modes whatever the scope, so a person choosing
    // between them has to be told it is not limited to enrolled repositories.
    const description = ATTACH_MODE_CHOICES.find((c) => c.value === 'scoped')?.description ?? '';
    expect(description).toContain(`${SESSION_START} your organization's ${POLICY_AND_REPORT}`);
    expect(description).not.toContain(PREVIOUS_POLICY_AND_REPORT);
  });

  it.each([
    ['the machine-wide notice', CONNECTION_FORWARDING_NOTICE],
    ['the scoped notice', CONNECTION_FORWARDING_NOTICE_SCOPED],
  ])('says the same about the policy pull and the report in %s', (_name, notice) => {
    expect(notice).toContain(`${SESSION_START} that deployment's ${POLICY_AND_REPORT}`);
    expect(notice).not.toContain(PREVIOUS_POLICY_AND_REPORT);
  });

  it('words the personal-device choice and mode line so they cannot read as "nothing else is sent"', () => {
    // The install report goes in both modes, so "only activity ... is sent"
    // would claim less than is sent. The activity is what is limited.
    const scoped = ATTACH_MODE_CHOICES.find((c) => c.value === 'scoped');
    expect(scoped?.description).toMatch(/Activity is sent only from repositories you enroll/);
    expect(CONNECTION_MODE_SCOPED).toMatch(
      /Activity is sent only from repositories you enroll with `aka enroll`/,
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
    // A scoped machine still pulls policy and sends a device report whenever a
    // session starts — both send without a scope verdict, by design, and the
    // sentence saying so is pinned above — so a notice that said "nothing else is
    // sent" would be false.
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/plugin forwards activity only from/i);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/aka enroll/);
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/stays on this machine/i);
    // The command check is where a scan is available, and a browser chat has none.
    expect(CONNECTION_FORWARDING_NOTICE_SCOPED).toMatch(/not a browser chat/i);
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
    expect(html).toContain(inMarkup(CONNECTION_FORWARDING_NOTICE_SCOPED));
    expect(html).not.toContain(inMarkup(CONNECTION_FORWARDING_NOTICE));
  });

  it('names a machine-wide attachment and keeps the machine-wide notice', () => {
    const html = render({
      settings: attached,
      onDetach: () => undefined,
      attachmentMode: 'machine',
    });
    expect(html).toContain(CONNECTION_MODE_MACHINE);
    expect(html).toContain(inMarkup(CONNECTION_FORWARDING_NOTICE));
    expect(html).not.toContain(inMarkup(CONNECTION_FORWARDING_NOTICE_SCOPED));
  });

  it('names no mode when the host reports none, and describes the wider case', () => {
    // Absent means "not reported". The machine-wide notice claims MORE is sent,
    // never less, so it is the one a row that cannot tell renders.
    const html = render({ settings: attached, onDetach: () => undefined });
    expect(html).not.toContain('data-slot="connection-mode"');
    expect(html).toContain(inMarkup(CONNECTION_FORWARDING_NOTICE));
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
