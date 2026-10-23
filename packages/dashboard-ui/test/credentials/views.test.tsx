// @vitest-environment jsdom
import {
  CREDENTIAL_LABEL_MAX_LENGTH,
  CREDENTIAL_OWNER_MAX_LENGTH,
  type CredentialStatus,
} from '@akasecurity/schema';
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
  rotationPolicyDays: null,
  statuses: [],
};

const DETAIL: CredentialDetailModel = {
  ...ITEM,
  ruleId: 'secrets/github-pat',
  firstSeen: '2026-10-01T00:00:00.000Z',
  sightingCount: 9,
  reference: null,
  rotationDueAt: null,
  exposedAt: null,
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
      'Status',
    ]);
    const cells = [...mounted.host.querySelectorAll('tbody td')].map((td) => td.textContent.trim());
    expect(cells).toEqual(['GITHUB_TOKENGitHub token', 'GitHub', '—', '2', '3', '4', '—', '']);
  });

  it('shows the owner, the last rotation and each status a credential carries', () => {
    list({
      items: [
        {
          ...ITEM,
          owner: 'Payments',
          lastRotated: '2026-07-01',
          rotationPolicyDays: 90,
          statuses: ['rotation_overdue'],
        },
      ],
    });
    const cells = [...mounted.host.querySelectorAll('tbody td')].map((td) => td.textContent.trim());
    expect(cells[2]).toBe('Payments');
    expect(cells[6]).not.toBe('—');
    expect(cells[7]).toBe('Rotation overdue');
  });

  const chip = (label: string) =>
    [
      ...mounted.host.querySelectorAll<HTMLButtonElement>('[aria-label="Filter by status"] button'),
    ].find((b) => b.textContent.startsWith(label));

  it('counts each chip by its own facet, not by the filtered total, and marks the one that is on', () => {
    const onStatus = vi.fn();
    list({
      items: [{ ...ITEM, statuses: ['rotation_overdue'] }],
      total: 3,
      status: 'rotation_overdue',
      onStatus,
      statusCounts: { all: 40, byStatus: { rotation_overdue: 3, exposed: 5 } },
    });
    expect(chip('All')?.textContent).toBe('All40');
    expect(chip('Rotation overdue')?.textContent).toBe('Rotation overdue3');
    expect(chip('All')?.getAttribute('aria-pressed')).toBe('false');
    expect(chip('Exposed')?.textContent).toBe('Exposed5');
    expect(chip('Rotation overdue')?.getAttribute('aria-pressed')).toBe('true');
    act(() => {
      chip('All')?.click();
    });
    expect(onStatus).toHaveBeenLastCalledWith(null);
    act(() => {
      chip('Rotation overdue')?.click();
    });
    expect(onStatus).toHaveBeenLastCalledWith('rotation_overdue');
  });

  it('shows no chips without a status callback, and chips without counts while none are known', () => {
    list();
    expect(mounted.host.querySelector('[aria-label="Filter by status"]')).toBeNull();
    list({ onStatus: vi.fn() });
    const chips = [...mounted.host.querySelectorAll('[aria-label="Filter by status"] button')].map(
      (b) => b.textContent,
    );
    expect(chips).toEqual(['All', 'Rotation overdue', 'Exposed']);
  });

  it('shows every status a credential carries, Exposed among them', () => {
    list({ items: [{ ...ITEM, statuses: ['rotation_overdue', 'exposed'] }] });
    expect(mounted.host.querySelectorAll('tbody td')[7]?.textContent).toBe(
      'Rotation overdueExposed',
    );
  });

  it('shows a status this build does not know as sent, rather than failing the list', () => {
    list({ items: [{ ...ITEM, statuses: ['broadly_shared' as unknown as CredentialStatus] }] });
    expect(mounted.host.querySelectorAll('tbody td')[7]?.textContent).toBe('broadly_shared');
  });

  it('ignores a status filter passed without chips, which would strand the reader', () => {
    list({ items: [], total: 0, status: 'rotation_overdue' });
    expect(text()).toContain('No credentials have been seen yet');
    expect(text()).not.toContain('rotation overdue');
  });

  it('names a filter status this build does not know as sent, rather than failing the list', () => {
    list({
      items: [],
      total: 0,
      status: 'broadly_shared' as unknown as CredentialStatus,
      onStatus: vi.fn(),
    });
    expect(text()).toContain('No credentials are broadly_shared.');
  });

  it('says no credential carries the status when the chip matches nothing', () => {
    list({ items: [], total: 0, status: 'rotation_overdue', onStatus: vi.fn() });
    expect(text()).toContain('No credentials are rotation overdue.');
    expect(text()).not.toContain('No credentials have been seen yet');
    list({ items: [], total: 0, status: 'rotation_overdue', onStatus: vi.fn(), search: 'stripe' });
    expect(text()).toContain('No credentials are rotation overdue in this search.');
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

  it('withholds the chip counts under an error', () => {
    list({
      items: [],
      total: 0,
      error: 'You need permission to view detections.',
      onStatus: vi.fn(),
      statusCounts: { all: 0, byStatus: { rotation_overdue: 0, exposed: 0 } },
    });
    expect(chip('All')?.textContent).toBe('All');
    expect(chip('Rotation overdue')?.textContent).toBe('Rotation overdue');
  });
});

describe('CredentialDetailView', () => {
  function detail(
    credential: CredentialDetailModel = DETAIL,
    label: Pick<
      CredentialDetailViewProps,
      | 'onSaveLabel'
      | 'labelError'
      | 'labelRefusal'
      | 'labelMaxLength'
      | 'onSaveRotation'
      | 'rotationError'
      | 'rotationRefusal'
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

  it('says an exposed credential is Exposed and when it was first seen in a live session', () => {
    detail({ ...DETAIL, statuses: ['exposed'], exposedAt: '2026-10-21T09:00:00.000Z' });
    // The badge in the header, then one sentence that leads with the word, not a second headline.
    expect(text()).toContain(
      'Exposed — this value was seen in a live LLM session, first 3 hours ago.',
    );
    expect(text().split('Exposed')).toHaveLength(3);
  });

  it('keeps the Exposed note when the status is set without a time, leaving out when', () => {
    detail({ ...DETAIL, statuses: ['exposed'], exposedAt: null });
    expect(text()).toContain(
      'Exposed — this value was seen in a live LLM session. Its linked finding below',
    );
  });

  it('says nothing of exposure for a credential no live session carried', () => {
    detail();
    expect(text()).not.toContain('Exposed');
    expect(text()).not.toContain('live LLM session, first');
  });

  it('says why a credential has no linked findings', () => {
    detail({ ...DETAIL, findings: [], projects: [], teams: [], harnesses: [] });
    expect(text()).toContain('No findings.');
    expect(text()).toContain('None seen');
  });
  describe('rotation details', () => {
    type Save = NonNullable<CredentialDetailViewProps['onSaveRotation']>;
    const field = (name: string) =>
      mounted.host.querySelector<HTMLInputElement>(`input[aria-label="${name}"]`);

    function fill(name: string, value: string) {
      const input = field(name);
      if (!input) throw new Error(`no ${name} input`);
      act(() => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
          input,
          value,
        );
        input.dispatchEvent(new Event('input', { bubbles: true }));
      });
    }

    const alert = () => mounted.host.querySelector('[role="alert"]')?.textContent;

    it('shows the owner, policy, due date and the overdue status', () => {
      detail({
        ...DETAIL,
        owner: 'Payments',
        lastRotated: '2026-01-01',
        rotationPolicyDays: 90,
        rotationDueAt: '2026-04-01T00:00:00.000Z',
        statuses: ['rotation_overdue'],
      });
      expect(text()).toContain('Payments');
      expect(text()).toContain('Every 90 days');
      expect(text()).toContain('Rotation overdue');
      expect(text()).toContain('months ago');
    });

    it('shows dashes and no status while nothing is set', () => {
      detail();
      expect(text()).not.toContain('Rotation overdue');
      expect(text()).not.toContain('Every');
      expect(button('Edit rotation')).toBeUndefined();
    });

    it('saves trimmed values, and clears an emptied field as null', async () => {
      const onSaveRotation = vi.fn<Save>().mockResolvedValue();
      detail(
        { ...DETAIL, owner: 'Payments', lastRotated: '2026-01-01', rotationPolicyDays: 30 },
        { onSaveRotation },
      );
      act(() => {
        button('Edit rotation')?.click();
      });
      expect(field('Owner')?.value).toBe('Payments');
      expect(field('Last rotated')?.value).toBe('2026-01-01');
      expect(field('Rotation policy in days')?.value).toBe('30');
      fill('Owner', '  Platform team ');
      fill('Last rotated', '2026-07-01');
      fill('Rotation policy in days', ' 90 ');
      await submit();
      expect(onSaveRotation).toHaveBeenLastCalledWith({
        owner: 'Platform team',
        lastRotated: '2026-07-01',
        rotationPolicyDays: 90,
      });
      expect(field('Owner')).toBeNull();
      act(() => {
        button('Edit rotation')?.click();
      });
      fill('Owner', ' ');
      fill('Last rotated', '');
      fill('Rotation policy in days', '');
      await submit();
      expect(onSaveRotation).toHaveBeenLastCalledWith({
        owner: null,
        lastRotated: null,
        rotationPolicyDays: null,
      });
    });

    it.each([
      ['0', 'A rotation policy is a whole number of days from 1 to 3650.'],
      ['3651', 'A rotation policy is a whole number of days from 1 to 3650.'],
      ['1.5', 'A rotation policy is a whole number of days from 1 to 3650.'],
      ['ninety', 'A rotation policy is a whole number of days from 1 to 3650.'],
    ])('refuses a policy of %s before saving', (value, message) => {
      detail(DETAIL, { onSaveRotation: vi.fn<Save>() });
      act(() => {
        button('Edit rotation')?.click();
      });
      fill('Rotation policy in days', value);
      expect(button('Save')?.disabled).toBe(true);
      expect(alert()).toBe(message);
    });

    // RENDERED_AT is 12:00 UTC on 2026-10-21, so one day ahead reaches 12:00 on the 22nd.
    it.each([
      ['today', '2026-10-21'],
      ['the next day, which is within a day of the render', '2026-10-22'],
    ])('accepts a last rotation on %s', (_name, value) => {
      detail(DETAIL, { onSaveRotation: vi.fn<Save>() });
      act(() => {
        button('Edit rotation')?.click();
      });
      fill('Last rotated', value);
      expect(button('Save')?.disabled).toBe(false);
      expect(alert()).toBeUndefined();
    });

    it('refuses a last rotation two days ahead', () => {
      detail(DETAIL, { onSaveRotation: vi.fn<Save>() });
      act(() => {
        button('Edit rotation')?.click();
      });
      fill('Last rotated', '2026-10-23');
      expect(button('Save')?.disabled).toBe(true);
      expect(alert()).toBe('The last rotation cannot be more than a day ahead.');
    });

    // A date input clears a value it cannot parse, so these reach the editor from the host.
    it.each([
      ['not a date', 'not-a-date'],
      ['an impossible day', '2026-02-30'],
      ['a month past December', '2026-13-01'],
    ])('refuses a last rotation the host hands in that is %s', (_name, value) => {
      detail({ ...DETAIL, lastRotated: value }, { onSaveRotation: vi.fn<Save>() });
      act(() => {
        button('Edit rotation')?.click();
      });
      expect(button('Save')?.disabled).toBe(true);
      expect(alert()).toBe('Enter the last rotation as a date.');
    });

    it.each([['1'], ['3650']])('accepts a policy of %s days, at the bound', async (value) => {
      const onSaveRotation = vi.fn<Save>().mockResolvedValue();
      detail(DETAIL, { onSaveRotation });
      act(() => {
        button('Edit rotation')?.click();
      });
      fill('Rotation policy in days', value);
      expect(alert()).toBeUndefined();
      await submit();
      expect(onSaveRotation).toHaveBeenLastCalledWith(
        expect.objectContaining({ rotationPolicyDays: Number(value) }),
      );
    });

    it('refuses an owner the host hands in over the bound, measured after trimming', () => {
      const long = 'x'.repeat(CREDENTIAL_OWNER_MAX_LENGTH + 1);
      detail({ ...DETAIL, owner: long }, { onSaveRotation: vi.fn<Save>() });
      act(() => {
        button('Edit rotation')?.click();
      });
      expect(button('Save')?.disabled).toBe(true);
      expect(alert()).toBe(
        `Owners are limited to ${String(CREDENTIAL_OWNER_MAX_LENGTH)} characters.`,
      );
      fill('Owner', `  ${'x'.repeat(CREDENTIAL_OWNER_MAX_LENGTH)}  `);
      expect(button('Save')?.disabled).toBe(false);
    });

    it('shows a status this build does not know as sent', () => {
      detail({ ...DETAIL, statuses: ['broadly_shared' as unknown as CredentialStatus] });
      expect(text()).toContain('broadly_shared');
    });

    it('shows the control locked with the reason when the reader may not edit it', () => {
      const onSaveRotation = vi.fn<Save>();
      detail(DETAIL, { onSaveRotation, rotationRefusal: 'You do not have enough permissions.' });
      const control = button('Edit rotation');
      expect(control?.getAttribute('aria-disabled')).toBe('true');
      expect(
        mounted.host.querySelector('[data-slot="credential-rotation-reason"]')?.textContent,
      ).toBe('You do not have enough permissions.');
      act(() => {
        control?.click();
      });
      expect(field('Owner')).toBeNull();
    });

    it('locks the control for a credential a secrets manager holds', () => {
      detail({ ...DETAIL, reference: 'vault://kv/payments#github' }, { onSaveRotation: vi.fn() });
      expect(button('Edit rotation')?.getAttribute('aria-disabled')).toBe('true');
      expect(
        mounted.host.querySelector('[data-slot="credential-rotation-reason"]')?.textContent,
      ).toContain('come from there');
    });

    it('keeps the editor open with the host error when a save fails', async () => {
      const onSaveRotation = vi.fn<Save>().mockRejectedValue(new Error('refused'));
      detail(DETAIL, { onSaveRotation, rotationError: 'You need permission to edit credentials.' });
      act(() => {
        button('Edit rotation')?.click();
      });
      fill('Owner', 'Payments');
      await submit();
      expect(field('Owner')?.value).toBe('Payments');
      expect(alert()).toBe('You need permission to edit credentials.');
    });

    it('returns focus to the control after a save and after Escape', async () => {
      detail(DETAIL, { onSaveRotation: vi.fn<Save>().mockResolvedValue() });
      act(() => {
        button('Edit rotation')?.click();
      });
      await submit();
      expect(document.activeElement).toBe(button('Edit rotation'));
      act(() => {
        button('Edit rotation')?.click();
      });
      act(() => {
        field('Owner')?.dispatchEvent(
          new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
        );
      });
      expect(field('Owner')).toBeNull();
      expect(document.activeElement).toBe(button('Edit rotation'));
    });
  });
});
