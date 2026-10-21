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
    chip: 'all',
    onChip: vi.fn(),
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
    expect(cells).toEqual(['GITHUB_TOKENGitHub token', 'GitHub', '—', '2', '3', '4', '—', 'OK']);
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

  it('shows the host error in place of the table', () => {
    list({ error: 'You need permission to view detections.' });
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      'You need permission to view detections.',
    );
    expect(mounted.host.querySelector('table')).toBeNull();
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

  it('lists where it is used: projects, teams with an Ungrouped bucket, and harness labels', () => {
    detail();
    expect(text()).toContain('acme/api');
    expect(text()).toContain('acme/web');
    expect(text()).toContain('Payments · 2 people');
    expect(text()).toContain('Ungrouped · 1 person');
    expect(text()).toContain('Claude Code');
    // A harness the label map does not know is shown by its id, not dropped.
    expect(text()).toContain('some-new-harness');
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
