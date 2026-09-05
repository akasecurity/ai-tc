import type { FindingFacets } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import {
  FindingLevelFilters,
  FindingsToolbarView,
} from '../../src/findings/FindingsToolbarView.tsx';
import { EMPTY_FILTERS } from '../../src/findings/meta.ts';

const facets: FindingFacets = {
  severity: [{ value: 'critical', count: 3 }],
  subtype: [{ value: 'aws-key', count: 3 }],
  provider: [{ value: 'claudecode', count: 2 }],
  action: [{ value: 'blocked', count: 1 }],
  status: [{ value: 'open', count: 1 }],
};

const TYPE_LEVEL = ['Severity', 'Type'] as const;
const FINDING_LEVEL = ['Provider', 'Action', 'Status'] as const;

function renderToolbar(props: Partial<Parameters<typeof FindingsToolbarView>[0]> = {}) {
  return renderToStaticMarkup(
    <FindingsToolbarView
      facets={facets}
      filters={EMPTY_FILTERS}
      onFiltersChange={vi.fn()}
      query=""
      onQueryChange={vi.fn()}
      {...props}
    />,
  );
}

function renderFindingLevel(props: Partial<Parameters<typeof FindingLevelFilters>[0]> = {}) {
  return renderToStaticMarkup(
    <FindingLevelFilters
      facets={facets}
      filters={EMPTY_FILTERS}
      onFiltersChange={vi.fn()}
      {...props}
    />,
  );
}

// The findings page splits its filters by the LEVEL each one acts on: severity
// and type select TYPES, while provider/action/status vary between the findings
// OF one type. The flat view is one list, so its toolbar carries both levels.
// The master/detail view renders no toolbar at all — each half sits beside what
// it narrows — which is why the finding-level three are their own component.
describe('FindingsToolbarView', () => {
  it('carries both filter levels and the search box', () => {
    const html = renderToolbar();
    for (const label of [...TYPE_LEVEL, ...FINDING_LEVEL]) {
      expect(html).toContain(`>${label}<`);
    }
    expect(html).toContain('Search findings…');
  });

  // The tally is page-level and lives under the page title. Beside a filter it
  // read as that filter's own result — and in the master/detail view it was
  // one no filter here could move, which reads as a control that stopped
  // working.
  it('renders no findings/types tally', () => {
    const html = renderToolbar();
    expect(html).not.toContain('findings ·');
    expect(html).not.toMatch(/\d+\s*types?</);
  });
});

describe('FindingLevelFilters', () => {
  it('renders the three finding-level dimensions and nothing above them', () => {
    const html = renderFindingLevel();
    for (const label of FINDING_LEVEL) {
      expect(html).toContain(`>${label}<`);
    }
    // Type-level controls belong with the type list, not beside the findings.
    for (const label of TYPE_LEVEL) {
      expect(html).not.toContain(`>${label}<`);
    }
    expect(html).not.toContain('Search findings…');
  });

  // A trigger states its own selection count, which is the only part of a
  // filter this render mode can see: the options live inside a Radix popover
  // that a static render never opens, so the per-option facet counts are not
  // asserted here.
  it('marks only the filtered dimensions active, with their selection count', () => {
    expect(renderFindingLevel()).not.toContain('bg-primary-tint');

    const html = renderFindingLevel({
      filters: { ...EMPTY_FILTERS, provider: ['claudecode', 'codex'] },
    });
    expect((html.match(/bg-primary-tint/g) ?? []).length).toBe(1);
    expect(html).toContain('>2<');
  });
});
