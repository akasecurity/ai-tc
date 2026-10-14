// @vitest-environment jsdom
//
// The web chat account grant's row, driven through real input: what Save sends
// for it is the answer on screen when the row was touched, and 'unchanged' when
// it was not. A server render cannot click, so it cannot see either.
import type { WorkspaceSettings } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { WorkspaceSettingsFormViewProps } from '../../src/settings/WorkspaceSettingsFormView.tsx';
import {
  WEB_CHAT_ACCOUNT_CHOICES,
  WEB_CHAT_CHOICES,
  WorkspaceSettingsFormView,
} from '../../src/settings/WorkspaceSettingsFormView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

type Saved = Parameters<WorkspaceSettingsFormViewProps['onSave']>[0];

const settings: WorkspaceSettings = {
  specVersion: 3,
  policy: 'redact',
  historicalAccess: 'session-only',
  dataSharesInPlace: true,
  vaultKeyCustody: 'file',
  vaultInlineReveal: 'masked',
  redactFallback: 'warn',
  bodyRetention: { enabled: false, retainDays: 30 },
  // A personal device, the machine the row is offered on.
  runMode: 'attached',
  controlPlane: { endpoint: 'https://aka.example.com', attachedAt: '2026-10-01T00:00:00.000Z' },
};

let mounted: MountedRoot;
let saved: Saved[];

beforeEach(() => {
  mounted = mountRoot();
  saved = [];
  renderRoot(
    mounted.root,
    <WorkspaceSettingsFormView
      settings={settings}
      attachmentMode="scoped"
      onSave={(changes) => {
        saved.push(changes);
      }}
    />,
  );
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

// The radio whose card holds a choice's own description: the radios carry no
// value attribute, and the two rows share their labels.
function choice(description: string | undefined): HTMLInputElement {
  if (description === undefined) throw new Error('no such choice');
  const card = [...mounted.host.querySelectorAll('label')].find((el) =>
    el.textContent.includes(description),
  );
  const input = card?.querySelector<HTMLInputElement>('input[type="radio"]') ?? null;
  if (input === null) throw new Error(`no choice described "${description.slice(0, 40)}"`);
  return input;
}

const describedAs = (
  choices: typeof WEB_CHAT_ACCOUNT_CHOICES,
  value: 'granted' | 'revoked',
): string | undefined => choices.find((c) => c.value === value)?.description;

function click(el: HTMLElement): void {
  act(() => {
    el.click();
  });
}

function save(): void {
  const button = [...mounted.host.querySelectorAll('button')].find((el) =>
    el.textContent.includes('Save changes'),
  );
  if (button === undefined) throw new Error('no Save button');
  click(button);
}

describe('the web chat account row', () => {
  it('sends the answer chosen on it, and leaves the capture grant unchanged', () => {
    const granted = choice(describedAs(WEB_CHAT_ACCOUNT_CHOICES, 'granted'));
    expect(granted.name).toBe('webChatAccountConsent');
    click(granted);
    save();
    expect(saved).toHaveLength(1);
    expect(saved[0]?.webChatAccountConsent).toBe('granted');
    expect(saved[0]?.webChatCaptureConsent).toBe('unchanged');
  });

  it('sends a revoke when it is toggled on and back off', () => {
    click(choice(describedAs(WEB_CHAT_ACCOUNT_CHOICES, 'granted')));
    click(choice(describedAs(WEB_CHAT_ACCOUNT_CHOICES, 'revoked')));
    save();
    expect(saved[0]?.webChatAccountConsent).toBe('revoked');
  });

  it('sends unchanged when only the capture row was answered', () => {
    click(choice(describedAs(WEB_CHAT_CHOICES, 'granted')));
    save();
    expect(saved[0]?.webChatCaptureConsent).toBe('granted');
    expect(saved[0]?.webChatAccountConsent).toBe('unchanged');
  });
});
