// @vitest-environment jsdom
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CredentialDetailView } from '../../src/credentials/CredentialDetailView.tsx';
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
  kind: 'GitHub token',
  provider: 'GitHub',
  owner: null,
  projectCount: 2,
  teamCount: 3,
  endpointCount: 4,
  lastRotated: null,
  lastSeen: '2026-10-21T11:00:00.000Z',
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
  function detail(credential: CredentialDetailModel = DETAIL) {
    const onBack = vi.fn();
    const onOpenFinding = vi.fn();
    renderRoot(
      mounted.root,
      <CredentialDetailView
        credential={credential}
        onBack={onBack}
        onOpenFinding={onOpenFinding}
        renderedAt={RENDERED_AT}
      />,
    );
    return { onBack, onOpenFinding };
  }

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
