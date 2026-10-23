// @vitest-environment jsdom
import { CREDENTIAL_LABEL_MAX_LENGTH } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CredentialDetailView,
  type CredentialDetailViewProps,
} from '../../src/credentials/CredentialDetailView.tsx';
import {
  CredentialsListView,
  type CredentialsListViewProps,
} from '../../src/credentials/CredentialsListView.tsx';
import { credentialDismissReasonLabel } from '../../src/credentials/dismissal.ts';
import type { CredentialDetailModel, CredentialListItem } from '../../src/credentials/types.ts';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const RENDERED_AT = Date.parse('2026-10-21T12:00:00.000Z');

const ITEM: CredentialListItem = {
  id: 'cred-1',
  variableName: 'GITHUB_TOKEN',
  label: null,
  displayName: 'GITHUB_TOKEN',
  kind: 'GitHub token',
  provider: 'GitHub',
  owner: null,
  projectCount: 2,
  teamCount: 3,
  endpointCount: 4,
  lastRotated: null,
  lastSeen: '2026-10-21T11:00:00.000Z',
  dismissal: null,
};

const DETAIL: CredentialDetailModel = {
  ...ITEM,
  ruleId: 'secrets/github-pat',
  firstSeen: '2026-10-01T00:00:00.000Z',
  sightingCount: 9,
  reference: null,
  projects: ['acme/api', 'acme/web'],
  teams: [
    { name: 'Payments', userCount: 2 },
    { name: null, userCount: 1 },
  ],
  harnesses: ['claude-code', 'some-new-harness'],
  findings: [
    {
      id: 'finding-1',
      name: 'GitHub Personal Access Token',
      severity: 'critical',
      detectedAt: '2026-10-20T12:00:00.000Z',
    },
  ],
};

let mounted: MountedRoot;
beforeEach(() => {
  mounted = mountRoot();
});
afterEach(() => {
  unmountMountedRoot(mounted);
});

const text = () => mounted.host.textContent;
const button = (label: string) =>
  [...mounted.host.querySelectorAll('button')].find((b) => b.textContent.includes(label));
// Dialogs portal out of the mounted host, into the document body.
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
const dialogButton = (label: string) =>
  [...(dialog()?.querySelectorAll('button') ?? [])].find((b) => b.textContent.includes(label));

function list(overrides: Partial<CredentialsListViewProps> = {}) {
  const props: CredentialsListViewProps = {
    items: [ITEM],
    total: 1,
    search: '',
    onSearch: vi.fn(),
    onSelect: vi.fn(),
    onExport: vi.fn(),
    onNextPage: vi.fn(),
    onPreviousPage: vi.fn(),
    hasNextPage: false,
    hasPreviousPage: false,
    pageStart: 1,
    renderedAt: RENDERED_AT,
    ...overrides,
  };
  renderRoot(mounted.root, <CredentialsListView {...props} />);
  return props;
}

describe('CredentialsListView', () => {
  it('renders the design columns, with a dash where no secrets manager supplies a value', () => {
    list();
    const headers = [...mounted.host.querySelectorAll('th')].map((th) => th.textContent);
    expect(headers).toEqual([
      'Name',
      'Provider',
      'Owner',
      'Projects',
      'Teams',
      'Endpoints',
      'Last rotated',
    ]);
    const cells = [...mounted.host.querySelectorAll('tbody td')].map((td) => td.textContent.trim());
    expect(cells).toEqual(['GITHUB_TOKENGitHub token', 'GitHub', '—', '2', '3', '4', '—']);
  });

  it('shows the display name, with the variable beside the kind once a label names it', () => {
    list({
      items: [
        { ...ITEM, id: 'cred-1', label: 'Deploy bot', displayName: 'Deploy bot' },
        {
          ...ITEM,
          id: 'cred-2',
          variableName: null,
          displayName: 'GitHub token · acme/api',
        },
      ],
      total: 2,
    });
    const names = [...mounted.host.querySelectorAll('tbody tr')].map(
      (tr) => tr.querySelector('td')?.textContent,
    );
    expect(names).toEqual([
      'Deploy botGitHub token · GITHUB_TOKEN',
      'GitHub token · acme/apiGitHub token',
    ]);
    expect(text()).not.toContain('Unnamed');
  });

  it('opens a credential on click and exports on request', () => {
    const props = list();
    act(() => {
      mounted.host.querySelector<HTMLElement>('tbody tr')?.click();
    });
    expect(props.onSelect).toHaveBeenCalledWith('cred-1');
    act(() => {
      button('Export')?.click();
    });
    expect(props.onExport).toHaveBeenCalledTimes(1);
  });

  it('pages, and shows where the page sits in the whole result', () => {
    const props = list({ total: 120, pageStart: 51, hasNextPage: true, hasPreviousPage: true });
    expect(text()).toContain('51–51 of 120');
    act(() => {
      button('Next')?.click();
    });
    expect(props.onNextPage).toHaveBeenCalledTimes(1);
    expect(text()).toContain('120 credentials');
  });

  it('tells an empty ledger apart from an empty search', () => {
    list({ items: [], total: 0 });
    expect(text()).toContain('No credentials have been seen yet');
    list({ items: [], total: 0, search: 'stripe' });
    expect(text()).toContain('Nothing matches this search.');
  });

  it('keeps the pager on an empty page past the first, and says the rows moved', () => {
    const props = list({ items: [], total: 120, pageStart: 101, hasPreviousPage: true });
    expect(text()).toContain('These rows moved while you were reading.');
    expect(text()).not.toContain('No credentials have been seen yet');
    act(() => {
      button('Previous')?.click();
    });
    expect(props.onPreviousPage).toHaveBeenCalledTimes(1);
  });

  it('shows placeholder rows, not an empty table, while the first page loads', () => {
    list({ items: [], total: 0, isLoading: true });
    expect(mounted.host.querySelector('table')).toBeNull();
    expect(mounted.host.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
    expect(text()).not.toContain('No credentials have been seen yet');
  });

  it('shows the host error in place of the table, the count and Export', () => {
    list({ items: [], total: 0, error: 'You need permission to view detections.' });
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      'You need permission to view detections.',
    );
    expect(mounted.host.querySelector('table')).toBeNull();
    expect(text()).toContain('Not available');
    expect(text()).not.toContain('0 credentials');
    expect(button('Export')?.disabled).toBe(true);
  });
});

describe('CredentialDetailView', () => {
  function detail(
    credential: CredentialDetailModel = DETAIL,
    label: Pick<
      CredentialDetailViewProps,
      'onSaveLabel' | 'labelError' | 'labelRefusal' | 'labelMaxLength'
    > = {},
  ) {
    const onBack = vi.fn();
    const onOpenFinding = vi.fn();
    renderRoot(
      mounted.root,
      <CredentialDetailView
        credential={credential}
        onBack={onBack}
        onOpenFinding={onOpenFinding}
        renderedAt={RENDERED_AT}
        {...label}
      />,
    );
    return { onBack, onOpenFinding };
  }

  const labelInput = () =>
    mounted.host.querySelector<HTMLInputElement>('input[aria-label="Credential label"]');

  function type(value: string) {
    const input = labelInput();
    if (!input) throw new Error('no label input');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }

  async function submit() {
    await act(async () => {
      button('Save')?.click();
      await Promise.resolve();
    });
  }

  it('shows no label control without a save callback', () => {
    detail();
    expect(button('Add label')).toBeUndefined();
    expect(button('Rename')).toBeUndefined();
  });

  it('heads a labelled credential with its label and keeps the variable as a detail', () => {
    detail({ ...DETAIL, label: 'Deploy bot', displayName: 'Deploy bot' });
    expect(mounted.host.querySelector('h2')?.textContent).toBe('Deploy bot');
    expect(text()).toContain('Variable');
    expect(text()).toContain('GITHUB_TOKEN');
  });

  it('heads an unnamed credential with its kind and project, never Unnamed', () => {
    detail({ ...DETAIL, variableName: null, displayName: 'GitHub token · acme/api' });
    expect(mounted.host.querySelector('h2')?.textContent).toBe('GitHub token · acme/api');
    expect(text()).not.toContain('Unnamed');
  });

  it('saves a trimmed label and closes the editor', async () => {
    const onSaveLabel = vi.fn<(label: string | null) => Promise<void>>().mockResolvedValue();
    detail(DETAIL, { onSaveLabel });
    act(() => {
      button('Add label')?.click();
    });
    expect(labelInput()?.maxLength).toBe(120);
    type('   ');
    expect(button('Save')?.disabled).toBe(true);
    type('  Deploy bot ');
    await submit();
    expect(onSaveLabel).toHaveBeenCalledWith('Deploy bot');
    expect(labelInput()).toBeNull();
  });

  it('clears a label, and cancels without saving', async () => {
    const onSaveLabel = vi.fn<(label: string | null) => Promise<void>>().mockResolvedValue();
    detail({ ...DETAIL, label: 'Deploy bot', displayName: 'Deploy bot' }, { onSaveLabel });
    act(() => {
      button('Rename')?.click();
    });
    expect(labelInput()?.value).toBe('Deploy bot');
    act(() => {
      button('Cancel')?.click();
    });
    expect(labelInput()).toBeNull();
    expect(onSaveLabel).not.toHaveBeenCalled();
    act(() => {
      button('Rename')?.click();
    });
    await act(async () => {
      button('Clear label')?.click();
      await Promise.resolve();
    });
    expect(onSaveLabel).toHaveBeenCalledWith(null);
  });

  it('shows a refused label control locked, with the reason, and opens no editor', () => {
    const onSaveLabel = vi.fn<(label: string | null) => Promise<void>>().mockResolvedValue();
    detail(DETAIL, { onSaveLabel, labelRefusal: 'You do not have enough permissions.' });
    const control = button('Add label');
    expect(control?.getAttribute('aria-disabled')).toBe('true');
    const reason = mounted.host.querySelector('[data-slot="credential-label-reason"]');
    expect(reason?.textContent).toBe('You do not have enough permissions.');
    expect(control?.getAttribute('aria-describedby')).toBe(reason?.id);
    act(() => {
      control?.click();
    });
    expect(labelInput()).toBeNull();
    expect(onSaveLabel).not.toHaveBeenCalled();
  });

  it('heads a credential with a blank display name by its kind, and a blank label counts as none', () => {
    detail({ ...DETAIL, variableName: null, label: '', displayName: '' });
    expect(mounted.host.querySelector('h2')?.textContent).toBe('GitHub token');
    detail({ ...DETAIL, label: '  ', displayName: 'GITHUB_TOKEN' }, { onSaveLabel: vi.fn() });
    expect(mounted.host.querySelector('h2')?.className).toContain('font-mono');
    expect(button('Add label')).toBeDefined();
    expect(text()).not.toContain('Variable');
  });

  it('bounds the label at CREDENTIAL_LABEL_MAX_LENGTH when the host names no length', () => {
    detail(DETAIL, { onSaveLabel: vi.fn(), labelMaxLength: undefined });
    act(() => {
      button('Add label')?.click();
    });
    expect(labelInput()?.maxLength).toBe(CREDENTIAL_LABEL_MAX_LENGTH);
  });

  it("bounds the label at the host's length when it names one", () => {
    detail(DETAIL, { onSaveLabel: vi.fn(), labelMaxLength: 40 });
    act(() => {
      button('Add label')?.click();
    });
    expect(labelInput()?.maxLength).toBe(40);
  });

  it('says why Save is off for a stored label longer than the bound', () => {
    const long = 'x'.repeat(50);
    detail(
      { ...DETAIL, label: long, displayName: long },
      { onSaveLabel: vi.fn(), labelMaxLength: 40 },
    );
    act(() => {
      button('Rename')?.click();
    });
    expect(button('Save')?.disabled).toBe(true);
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      'Labels are limited to 40 characters.',
    );
  });

  it('closes the editor onto the locked control when a refusal arrives, keeping focus', () => {
    const onSaveLabel = vi.fn<(label: string | null) => Promise<void>>().mockResolvedValue();
    detail(DETAIL, { onSaveLabel });
    act(() => {
      button('Add label')?.click();
    });
    expect(labelInput()).not.toBeNull();
    detail(DETAIL, { onSaveLabel, labelRefusal: 'You do not have enough permissions.' });
    expect(labelInput()).toBeNull();
    expect(button('Add label')?.getAttribute('aria-disabled')).toBe('true');
    expect(document.activeElement).toBe(button('Add label'));
  });

  it('gives a blank refusal a reason rather than an empty line', () => {
    detail(DETAIL, { onSaveLabel: vi.fn(), labelRefusal: '  ' });
    const control = button('Add label');
    expect(control?.getAttribute('aria-disabled')).toBe('true');
    expect(mounted.host.querySelector('[data-slot="credential-label-reason"]')?.textContent).toBe(
      "You can't label this credential.",
    );
  });

  it('says a save failed when the host gives no reason, and clears it on reopening', async () => {
    const onSaveLabel = vi
      .fn<(label: string | null) => Promise<void>>()
      .mockRejectedValue(new Error('refused'));
    detail(DETAIL, { onSaveLabel });
    act(() => {
      button('Add label')?.click();
    });
    expect(mounted.host.querySelector('[role="alert"]')).toBeNull();
    type('Deploy bot');
    await submit();
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      "Couldn't save the label.",
    );
    act(() => {
      button('Cancel')?.click();
    });
    act(() => {
      button('Add label')?.click();
    });
    expect(mounted.host.querySelector('[role="alert"]')).toBeNull();
  });

  it('returns focus to the label control after a save, a cancel and Escape', async () => {
    const onSaveLabel = vi.fn<(label: string | null) => Promise<void>>().mockResolvedValue();
    detail(DETAIL, { onSaveLabel });
    act(() => {
      button('Add label')?.click();
    });
    type('Deploy bot');
    await submit();
    expect(document.activeElement).toBe(button('Add label'));
    act(() => {
      button('Add label')?.click();
    });
    act(() => {
      button('Cancel')?.click();
    });
    expect(document.activeElement).toBe(button('Add label'));
    act(() => {
      button('Add label')?.click();
    });
    act(() => {
      labelInput()?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });
    expect(labelInput()).toBeNull();
    expect(document.activeElement).toBe(button('Add label'));
  });

  it('keeps the editor open with the host error when a save fails', async () => {
    const onSaveLabel = vi
      .fn<(label: string | null) => Promise<void>>()
      .mockRejectedValue(new Error('refused'));
    detail(DETAIL, { onSaveLabel, labelError: 'You need permission to label credentials.' });
    act(() => {
      button('Add label')?.click();
    });
    type('Deploy bot');
    await submit();
    expect(labelInput()?.value).toBe('Deploy bot');
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      'You need permission to label credentials.',
    );
  });

  it('marks a credential no secrets manager references as detected only', () => {
    detail();
    expect(text()).toContain('Detected only');
    expect(text()).toContain('Not linked to a secrets manager');
    detail({ ...DETAIL, reference: 'vault://kv/payments#github' });
    expect(text()).not.toContain('Detected only');
    expect(text()).toContain('vault://kv/payments#github');
  });

  it('names the kind and variable once, in the header', () => {
    detail();
    expect(text()).not.toContain('Variable name');
    expect(text().split('GITHUB_TOKEN')).toHaveLength(2);
    expect(text().split('GitHub token')).toHaveLength(2);
  });

  it('lists where it is used: projects, teams with an Ungrouped bucket, and harness labels', () => {
    detail();
    expect(text()).toContain('acme/api');
    expect(text()).toContain('acme/web');
    expect(text()).toContain('Payments · 2 people');
    expect(text()).toContain('Ungrouped · 1 person');
    expect(text()).toContain('Claude Code');
    // A harness the label map does not know is shown by its id, not dropped.
    expect(text()).toContain('some-new-harness');
    detail({ ...DETAIL, harnesses: ['constructor'] });
    expect(text()).toContain('constructor');
    expect(text()).toContain('Seen on 4 endpoints.');
  });

  it('opens a linked finding, and goes back to the list', () => {
    const { onBack, onOpenFinding } = detail();
    act(() => {
      button('GitHub Personal Access Token')?.click();
    });
    expect(onOpenFinding).toHaveBeenCalledWith('finding-1');
    act(() => {
      button('All credentials')?.click();
    });
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it('says why a credential has no linked findings', () => {
    detail({ ...DETAIL, findings: [], projects: [], teams: [], harnesses: [] });
    expect(text()).toContain('No findings.');
    expect(text()).toContain('None seen');
  });
});

describe('CredentialsListView dismissed toggle', () => {
  it('shows no toggle without a handler', () => {
    list();
    expect(button('Dismissed')).toBeUndefined();
  });

  it('toggles the dismissed set, showing its count and whether it is on', () => {
    const onDismissedChange = vi.fn();
    list({ onDismissedChange, dismissedCount: 4 });
    const toggle = button('Dismissed');
    expect(toggle?.textContent).toBe('Dismissed · 4');
    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    act(() => {
      toggle?.click();
    });
    expect(onDismissedChange).toHaveBeenCalledWith(true);

    list({ onDismissedChange, dismissedCount: 4, dismissed: true });
    expect(button('Dismissed')?.getAttribute('aria-pressed')).toBe('true');
    act(() => {
      button('Dismissed')?.click();
    });
    expect(onDismissedChange).toHaveBeenLastCalledWith(false);
  });

  it('shows the toggle without a count when the host gives none', () => {
    list({ onDismissedChange: vi.fn() });
    expect(button('Dismissed')?.textContent).toBe('Dismissed');
  });

  it('names a reason it has no label for by the reason itself, never an empty label', () => {
    expect(credentialDismissReasonLabel('some-new-reason' as never)).toBe('some-new-reason');
  });

  it('names the reason on a dismissed row', () => {
    list({
      items: [
        {
          ...ITEM,
          dismissal: { reason: 'false-positive', dismissedAt: '2026-10-20T00:00:00.000Z' },
        },
      ],
      dismissed: true,
      onDismissedChange: vi.fn(),
    });
    expect(mounted.host.querySelector('tbody td')?.textContent).toContain(
      'Dismissed: Not a credential',
    );
  });

  it('says no credential is dismissed rather than none seen', () => {
    list({ items: [], total: 0, dismissed: true, onDismissedChange: vi.fn() });
    expect(text()).toContain('No credentials are dismissed.');
    expect(text()).not.toContain('No credentials have been seen yet');
  });
});

describe('CredentialDetailView dismiss, restore and delete', () => {
  function detail(
    credential: CredentialDetailModel = DETAIL,
    actions: Pick<
      CredentialDetailViewProps,
      'onDismiss' | 'onRestore' | 'onDelete' | 'actionError'
    > = {},
  ) {
    renderRoot(
      mounted.root,
      <CredentialDetailView
        credential={credential}
        onBack={vi.fn()}
        onOpenFinding={vi.fn()}
        renderedAt={RENDERED_AT}
        {...actions}
      />,
    );
  }

  const DISMISSED: CredentialDetailModel = {
    ...DETAIL,
    dismissal: { reason: 'test-or-example', dismissedAt: '2026-10-21T09:00:00.000Z' },
  };

  function pick(label: string) {
    const input = [...(dialog()?.querySelectorAll('label') ?? [])]
      .find((l) => l.textContent.includes(label))
      ?.querySelector('input');
    if (!input) throw new Error(`no reason ${label}`);
    act(() => {
      input.click();
    });
  }

  it('shows no action without its handler', () => {
    detail(DISMISSED);
    expect(button('Dismiss')).toBeUndefined();
    expect(button('Delete')).toBeUndefined();
    expect(button('Restore')).toBeUndefined();
    // The dismissal itself still shows.
    expect(text()).toContain('Test or example data');
  });

  it('dismisses for the reason picked, worded for a credential, and closes', async () => {
    const onDismiss = vi.fn<(reason: string) => Promise<void>>().mockResolvedValue();
    detail(DETAIL, { onDismiss });
    act(() => {
      button('Dismiss')?.click();
    });
    expect(dialog()?.textContent).toContain('New sightings are still recorded');
    for (const label of ['Accepted risk', 'Not a credential', 'Test or example data']) {
      expect(dialog()?.textContent).toContain(label);
    }
    expect(dialogButton('Dismiss credential')?.disabled).toBe(true);
    pick('Not a credential');
    await act(async () => {
      dialogButton('Dismiss credential')?.click();
      await Promise.resolve();
    });
    expect(onDismiss).toHaveBeenCalledWith('false-positive');
    expect(dialog()).toBeNull();
  });

  it("keeps the dialog open with the host's reason when the dismissal fails", async () => {
    const onDismiss = vi.fn<(reason: string) => Promise<void>>().mockRejectedValue(new Error('x'));
    detail(DETAIL, { onDismiss, actionError: 'You do not have enough permissions.' });
    act(() => {
      button('Dismiss')?.click();
    });
    pick('Accepted risk');
    await act(async () => {
      dialogButton('Dismiss credential')?.click();
      await Promise.resolve();
    });
    expect(dialog()?.querySelector('[role="alert"]')?.textContent).toBe(
      'You do not have enough permissions.',
    );
  });

  it('shows a dismissed credential with its reason and when, and restores it', async () => {
    const onRestore = vi.fn<() => Promise<void>>().mockResolvedValue();
    detail(DISMISSED, { onRestore, onDismiss: vi.fn() });
    expect(text()).toContain('Dismissed');
    expect(text()).toContain('Test or example data · 3 hours ago');
    expect(button('Dismiss')).toBeUndefined();
    await act(async () => {
      button('Restore')?.click();
      await Promise.resolve();
    });
    expect(onRestore).toHaveBeenCalledTimes(1);
  });

  it('says a failed restore failed', async () => {
    const onRestore = vi.fn<() => Promise<void>>().mockRejectedValue(new Error('x'));
    detail(DISMISSED, { onRestore });
    await act(async () => {
      button('Restore')?.click();
      await Promise.resolve();
    });
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      "Couldn't update this credential.",
    );
  });

  it('confirms a delete with what goes, what stays in history, and that the value can come back', async () => {
    const onDelete = vi.fn<() => Promise<void>>().mockResolvedValue();
    detail(DETAIL, { onDelete });
    act(() => {
      button('Delete')?.click();
    });
    const copy = dialog()?.textContent ?? '';
    expect(copy).toContain('Delete this credential?');
    expect(copy).toContain('its 9 sightings and their links to findings.');
    expect(copy).toContain('The findings and the activity that carried the value stay in history.');
    expect(copy).toContain('it is recorded as a new credential');
    expect(copy).not.toContain('Nothing remembers');
    expect(copy).toContain('dismiss it instead');
    act(() => {
      dialogButton('Cancel')?.click();
    });
    expect(onDelete).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();

    act(() => {
      button('Delete')?.click();
    });
    await act(async () => {
      dialogButton('Delete credential')?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  const escape = () => {
    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });
  };

  it("keeps the delete dialog open with the host's reason, and Delete live again, when the delete fails", async () => {
    const onDelete = vi.fn<() => Promise<void>>().mockRejectedValue(new Error('x'));
    detail(DETAIL, { onDelete, actionError: 'Credential not found' });
    act(() => {
      button('Delete')?.click();
    });
    await act(async () => {
      dialogButton('Delete credential')?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
    expect(dialog()?.querySelector('[role="alert"]')?.textContent).toBe('Credential not found');
    expect(dialogButton('Delete credential')?.disabled).toBe(false);
  });

  it('cannot be closed while the host is still deleting, and reopens without a stale failure', async () => {
    let reject: (err: Error) => void = () => undefined;
    const onDelete = vi.fn<() => Promise<void>>(
      () =>
        new Promise((_resolve, rejectWith) => {
          reject = rejectWith;
        }),
    );
    detail(DETAIL, { onDelete });
    act(() => {
      button('Delete')?.click();
    });
    act(() => {
      dialogButton('Delete credential')?.click();
    });
    expect(dialogButton('Cancel')?.disabled).toBe(true);
    escape();
    expect(dialog()).not.toBeNull();

    await act(async () => {
      reject(new Error('x'));
      await Promise.resolve();
    });
    expect(dialog()?.querySelector('[role="alert"]')).not.toBeNull();
    escape();
    expect(dialog()).toBeNull();
    act(() => {
      button('Delete')?.click();
    });
    expect(dialog()?.querySelector('[role="alert"]')).toBeNull();
  });

  it('promises a restore only when the host offers one', () => {
    detail(DETAIL, { onDismiss: vi.fn() });
    act(() => {
      button('Dismiss')?.click();
    });
    expect(dialog()?.textContent).not.toContain('restore');
    escape();
    detail(DETAIL, { onDismiss: vi.fn(), onRestore: vi.fn() });
    act(() => {
      button('Dismiss')?.click();
    });
    expect(dialog()?.textContent).toContain('You can restore it at any time.');
  });

  it('counts one sighting in the singular', () => {
    detail({ ...DETAIL, sightingCount: 1 }, { onDelete: vi.fn() });
    act(() => {
      button('Delete')?.click();
    });
    expect(dialog()?.textContent).toContain('its 1 sighting and');
  });
});
