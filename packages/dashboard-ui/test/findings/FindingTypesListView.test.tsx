import type { FindingTypeSummary } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { FindingTypesListView } from '../../src/findings/FindingTypesListView.tsx';

function type(over: Partial<FindingTypeSummary> = {}): FindingTypeSummary {
  return {
    id: 'aws-key',
    category: 'secret',
    subtype: 'aws-key',
    severity: 'critical',
    detection: { id: 'aws-key', name: null },
    policy: { id: 'category:secret', name: 'secret' },
    instanceCount: 142,
    providers: ['claudecode'],
    aggregateAction: 'blocked',
    latestDetectedAt: '2026-01-01T00:00:00.000Z',
    status: 'open',
    ...over,
  };
}

function render(props: Partial<Parameters<typeof FindingTypesListView>[0]> = {}) {
  return renderToStaticMarkup(
    <FindingTypesListView
      types={[type()]}
      activeId=""
      onSelect={vi.fn()}
      query=""
      onQueryChange={vi.fn()}
      severityCounts={
        new Map([
          ['critical', 12],
          ['high', 31],
        ])
      }
      selectedSeverities={[]}
      onSeverityChange={vi.fn()}
      {...props}
    />,
  );
}

describe('FindingTypesListView', () => {
  it('renders the four things a type row carries, and nothing per-finding', () => {
    const html = render();
    expect(html).toContain('aws-key'); // the name
    expect(html).toContain('Secret'); // the category label
    expect(html).toContain('142'); // the count
    // The badge writes the value lowercase and capitalizes it in CSS.
    expect(html).toContain('>critical<'); // the severity badge
    // Location, provider and action vary between one type's findings, so they
    // belong to the detail panel — a row here must not fold any of them.
    expect(html).not.toContain('claudecode');
    expect(html).not.toContain('blocked');
  });

  // The one place this list is cheaper than the table it replaced: with no
  // relative label there is no clock to thread, so it cannot render one string
  // on the server and a different one at hydration.
  it('takes no render instant, because it renders no time', () => {
    expect(render()).not.toContain('ago');
    expect(Object.keys(type())).toContain('latestDetectedAt');
  });

  it('marks the active row and only that row', () => {
    const types = [type(), type({ id: 'github-pat', subtype: 'github-pat' })];
    const html = render({ types, activeId: 'github-pat' });
    expect((html.match(/aria-current="true"/g) ?? []).length).toBe(1);
    // The selected row is the one carrying it — the marker sits on the same
    // element as that row's name.
    const marked = /<button[^>]*aria-current="true"[\s\S]*?<\/button>/.exec(html)?.[0] ?? '';
    expect(marked).toContain('github-pat');
    expect(marked).not.toContain('aws-key');
  });

  // Severity narrows TYPES (every finding of one rule shares it), so its
  // control belongs beside the type list rather than in the page toolbar.
  it('renders every severity in fixed order with its count, selected or not', () => {
    const html = render();
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      expect(html).toContain(`>${sev}<`);
    }
    // Counts come from the facet; a severity the facet omits reads 0 rather
    // than dropping out of the row and shifting the ones beside it.
    expect(html).toContain('>12<');
    expect(html).toContain('>31<');
    expect((html.match(/>0</g) ?? []).length).toBe(2);
  });

  it('marks only the selected severities pressed', () => {
    expect((render().match(/aria-pressed="true"/g) ?? []).length).toBe(0);
    const html = render({ selectedSeverities: ['critical', 'low'] });
    expect((html.match(/aria-pressed="true"/g) ?? []).length).toBe(2);
  });

  // A page can arrive EMPTY and still have somewhere to go back to: the caller
  // appends the selected type to page 0 out of sort order, and dropping that
  // repeat when paging reaches its natural position can empty the page. Gated on
  // the row count, the footer carrying Previous vanished at exactly the moment
  // it was the only way out — a dead end, not a cosmetic gap.
  it('keeps the paginator on an empty page so Previous is still reachable', () => {
    const html = render({
      types: [],
      hasPreviousPage: true,
      hasNextPage: false,
      onNextPage: vi.fn(),
      onPreviousPage: vi.fn(),
      // The state a deduped-empty page really arrives in: page 2 of a 51-type
      // list whose 51st was appended to page 0 and dropped as a repeat here.
      pageStart: 52,
      total: 51,
    });
    expect(html).toContain('data-slot="pagination-previous"');

    // And the label beside it must not read backwards. The range branch would
    // render `52–51 of 51 types` — pageStart to pageStart-1 — directly above the
    // button that is the only way out. Reading the STATUS is the half the
    // original pair of cases omitted, which is how that shipped.
    const status = /pagination-status[^>]*>([^<]*)</.exec(html)?.[1];
    expect(status).toBe('0 shown');
  });

  it('still omits the paginator when there is nowhere to go at all', () => {
    const html = render({
      types: [],
      hasPreviousPage: false,
      hasNextPage: false,
      onNextPage: vi.fn(),
      onPreviousPage: vi.fn(),
    });
    expect(html).not.toContain('data-slot="pagination"');
  });

  it('renders the caller empty state instead of the default when given one', () => {
    expect(render({ types: [] })).toContain('No types match these filters.');
    expect(render({ types: [], emptyState: 'Nothing captured yet' })).toContain(
      'Nothing captured yet',
    );
  });

  // Same rule the flat table follows: a footer with no way to advance is a
  // paginator that lies about there being more.
  it('renders the pagination footer only when the caller can page', () => {
    expect(render()).not.toContain('Previous');
    const paged = render({ onNextPage: vi.fn(), pageStart: 1, total: 214 });
    expect(paged).toContain('Previous');
    expect(paged).toContain('1–1 of 214 types');
  });
});
