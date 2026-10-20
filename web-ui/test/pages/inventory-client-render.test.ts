import type { InventorySelection } from '@akasecurity/dashboard-ui';
import type { ProjectSummary, SensitiveDataClass } from '@akasecurity/schema';
import type React from 'react';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// InventoryClient reaches the router through the shared navigation hook, which
// throws outside a real Next app. Nothing calls it under a static render.
vi.mock('next/navigation', () => ({
  usePathname: () => '/inventory',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { InventoryClient } = await import('../../app/(app)/inventory/InventoryClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const PROJECT: ProjectSummary = {
  id: 'proj-1',
  name: 'payments-api',
  repo: 'acme/payments-api',
  visibility: 'private',
  language: 'TypeScript',
  policyDefault: 'approved',
  updatedAt: '2026-10-15T10:00:00.000Z',
  accessCounts: { open: 3, approved: 0, blocked: 2, total: 5 },
  findingsCount: 0,
};

const OPEN_PROJECT: InventorySelection = {
  view: 'type',
  harness: null,
  type: 'project',
  item: { type: 'project', id: PROJECT.id },
};

function render(blockedError: string | null, sensitiveData: SensitiveDataClass[] = []): string {
  const client = createElement(InventoryClient, {
    harnesses: [],
    assetGroups: [],
    projects: [PROJECT],
    active: OPEN_PROJECT,
    assetDetail: null,
    blocked: [],
    blockedError,
    sensitiveData,
    sensitiveDataError: null,
    harnessEvents: { counts: { block: 0, redact: 0, warn: 0 }, items: [] },
    renderedAt: Date.parse('2026-10-15T12:00:00.000Z'),
    locale: 'en-US',
  });
  return renderToStaticMarkup(
    createElement(NavigationTransitionProvider, null, client as React.ReactElement),
  );
}

describe('the opened project’s withheld files', () => {
  it('shows a failed read as a failure, not as files withheld by policy', () => {
    const html = render('the project is not in the local store');
    expect(html).toContain(
      'Couldn&#x27;t load the withheld files: the project is not in the local store',
    );
    expect(html).not.toContain('withheld by the project&#x27;s policy');
  });

  it('attributes withheld files the list does not show to policy when the read succeeded', () => {
    expect(render(null)).toContain('2 files are withheld by the project&#x27;s policy');
  });
});

describe('the opened project’s sensitive data', () => {
  it('lists the categories the read returned', () => {
    const html = render(null, [
      {
        category: 'secret',
        files: 3,
        severity: 'high',
        lastDetectedAt: '2026-10-15T11:00:00.000Z',
      },
    ]);
    expect(html).toContain('Sensitive data present');
    expect(html).toContain('3 files');
  });
});
