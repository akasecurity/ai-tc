import type { FindingLocationSummary } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { FindingLocationsListView } from '../../src/findings/FindingLocationsListView.tsx';

// A fixed instant every case renders against, so the relative labels below are
// a property of the fixture rather than of when the suite ran.
const NOW = Date.parse('2026-01-01T12:00:00.000Z');

function location(over: Partial<FindingLocationSummary> = {}): FindingLocationSummary {
  return {
    id: 'acme%2Fapi/cfg%2F.env',
    repo: 'acme/api',
    file: 'cfg/.env',
    instanceCount: 12,
    maxSeverity: 'critical',
    latestDetectedAt: '2026-01-01T10:00:00.000Z',
    status: 'open',
    ruleIds: ['aws-key'],
    ...over,
  };
}

function render(props: Partial<Parameters<typeof FindingLocationsListView>[0]> = {}) {
  return renderToStaticMarkup(
    <FindingLocationsListView
      locations={[location()]}
      activeId=""
      onSelect={vi.fn()}
      renderedAt={NOW}
      {...props}
    />,
  );
}

describe('FindingLocationsListView', () => {
  it('renders every fold a location row carries', () => {
    const html = render();
    expect(html).toContain('acme/api'); // the repo, as context
    expect(html).toContain('cfg/.env'); // the file, as the row's subject
    expect(html).toContain('12'); // the count
    expect(html).toContain('aws-key'); // the rules seen there
    // The badge writes the value lowercase and capitalizes it in CSS.
    expect(html).toContain('>critical<');
    // Relative to the instant passed in, never to a clock read here — and in
    // the short, locale-free form, so this assertion holds on any runner.
    expect(html).toContain('2h');
  });

  // The count is short enough for the column, and the exact number stays
  // reachable — compact notation rounds across its own boundary, so a reader
  // cannot tell '10k' from ten thousand without it.
  it('shortens a large count and keeps the exact one on the title', () => {
    const html = render({ locations: [location({ instanceCount: 1234 })] });
    expect(html).toContain('>1.2k<');
    expect(html).toContain('title="1,234 findings"');
    // The long form is NOT what the column shows.
    expect(html).not.toContain('>1,234<');
  });

  it('leaves a small count alone, and says "finding" once', () => {
    const one = render({ locations: [location({ instanceCount: 1 })] });
    expect(one).toContain('>1<');
    expect(one).toContain('title="1 finding"');

    const few = render({ locations: [location({ instanceCount: 486 })] });
    expect(few).toContain('>486<');
    expect(few).toContain('title="486 findings"');
  });

  // The bucket a finding lands in when its event recorded neither key. It is
  // often the largest location in a real store, and the tree this replaced
  // rendered it as a plain div — visible, and impossible to open.
  it('renders the unnamed bucket, and makes it selectable like any other row', () => {
    const html = render({
      locations: [location({ id: '/', repo: '', file: '', ruleIds: [] })],
    });
    expect(html).toContain('No repository recorded');
    expect(html).toContain('No file recorded');
    // A button, not a div — the whole point of giving it a `?loc=` token. The
    // tree this replaced rendered it as a div on purpose, because no filter
    // could name the empty string; counting rather than merely finding one is
    // what makes this fail if the old conditional ever comes back, since the
    // fixture is a single row and a div would leave zero.
    expect((html.match(/<button/g) ?? []).length).toBe(1);
  });

  // The read returns every distinct rule, so the row can say how many it is not
  // showing. Counting the remainder off the SLICE instead of the whole list
  // always yields zero, and the row then claims to show everything it has.
  it('bounds the rule chips it spells out and counts the rest against the whole list', () => {
    const html = render({
      locations: [
        location({ ruleIds: ['aws-key', 'github-token', 'slack-token', 'stripe-key', 'gcp-key'] }),
      ],
    });
    expect(html).toContain('aws-key');
    expect(html).toContain('github-token');
    expect(html).toContain('slack-token');
    // Five rules, three spelled out.
    expect(html).toContain('+2 more');
    // …and the two it elides are still reachable. `+2 more` names a count and
    // not the rules, and the panel beside this row lists findings rather than
    // distinct rules, so without this the two hidden names appear nowhere at all.
    expect(html).toContain('title="aws-key\ngithub-token\nslack-token\nstripe-key\ngcp-key"');
    // Not rendered as a chip — the point is that it is recoverable, not shown.
    expect(html).not.toContain('>stripe-key<');
  });

  it('says nothing about a remainder when every rule fits', () => {
    const html = render({ locations: [location({ ruleIds: ['aws-key', 'github-token'] })] });
    expect(html).not.toContain('more');
  });

  it('marks the selected row, and only it', () => {
    const html = render({
      locations: [location(), location({ id: 'other', file: 'src/db.ts' })],
      activeId: 'other',
    });
    expect((html.match(/aria-current="true"/g) ?? []).length).toBe(1);
  });

  it('explains an empty list, and defers to the host when it offers a reason', () => {
    expect(render({ locations: [] })).toContain('No locations match these filters');
    expect(render({ locations: [], emptyState: 'Nothing captured yet' })).toContain(
      'Nothing captured yet',
    );
  });

  // A page can arrive EMPTY and still have somewhere to go back to: the caller
  // appends the selected location to page 0 out of sort order, and dropping that
  // repeat when paging reaches its natural position empties the page. Gated on
  // the row count, the footer carrying Previous vanishes at exactly the moment
  // it is the only way out.
  it('keeps the paginator on an empty page so Previous is still reachable', () => {
    const html = render({
      locations: [],
      hasPreviousPage: true,
      hasNextPage: false,
      onNextPage: vi.fn(),
      onPreviousPage: vi.fn(),
      // The state a deduped-empty page really arrives in: page 2 of a 51-row
      // list whose 51st was appended to page 0 and dropped as a repeat here.
      pageStart: 52,
      total: 51,
    });
    expect(html).toContain('data-slot="pagination-previous"');

    // And the label beside it must not read backwards. The range branch would
    // render `52–51 of 51 locations` — pageStart to pageStart-1 — directly above
    // the button that is the only way out.
    const status = /pagination-status[^>]*>([^<]*)</.exec(html)?.[1];
    expect(status).toBe('0 shown');
  });

  it('states the range it is showing when the page has rows', () => {
    const html = render({
      locations: [location(), location({ id: 'other', file: 'src/db.ts' })],
      hasNextPage: true,
      onNextPage: vi.fn(),
      onPreviousPage: vi.fn(),
      pageStart: 51,
      total: 340,
    });
    const status = /pagination-status[^>]*>([^<]*)</.exec(html)?.[1];
    expect(status).toBe('51–52 of 340 locations');
  });

  it('still omits the paginator when there is nowhere to go at all', () => {
    const html = render({
      locations: [],
      hasPreviousPage: false,
      hasNextPage: false,
      onNextPage: vi.fn(),
      onPreviousPage: vi.fn(),
    });
    expect(html).not.toContain('data-slot="pagination"');
  });
});
