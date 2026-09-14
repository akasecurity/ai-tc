import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// DataSharesClient calls usePathname() directly, and the shared navigation
// hook it uses calls useRouter() — both throw outside a real Next app, so a
// bare render needs them stubbed. Renders here are static (no effects run
// under renderToStaticMarkup), so a no-op router is enough: nothing calls it.
vi.mock('next/navigation', () => ({
  usePathname: () => '/data-shares',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { DataSharesClient } = await import('../../app/(app)/data-shares/DataSharesClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

function group(kind: 'provider' | 'internal' | 'external' | 'ip', total: number) {
  return {
    kind,
    total,
    items: [
      {
        id: `dest-${kind}`,
        kind,
        name: `Destination (${kind})`,
        host: 'example.com',
        category: 'Cloud platform',
        trust: kind === 'ip' ? ('ip' as const) : ('recognized' as const),
        status: 'allowed' as const,
        isCustom: false,
        lastSeen: '2026-07-01T00:00:00.000Z',
        endpointCount: 1,
        callSiteCount: 1,
        transports: ['https' as const],
        dataClasses: ['pii' as const],
        review: { needsReview: false, reasons: [] },
        network: null,
        endpoints: [],
      },
    ],
  };
}

function reviewItem() {
  return {
    id: 'dest-review-1',
    kind: 'ip' as const,
    name: '203.0.113.0',
    host: '203.0.113.0',
    trust: 'ip' as const,
    status: 'review' as const,
    review: { needsReview: true, reasons: ['raw_ip' as const] },
    topDataClass: 'none' as const,
    callSiteCount: 1,
    lastSeen: '2026-07-01T00:00:00.000Z',
  };
}

function destinationDetail() {
  return {
    id: 'dest-provider',
    kind: 'provider' as const,
    name: 'Okta',
    host: 'okta.com',
    category: 'Identity',
    trust: 'recognized' as const,
    status: 'allowed' as const,
    isCustom: false,
    lastSeen: '2026-07-01T00:00:00.000Z',
    note: null,
    transports: ['https' as const],
    dataClasses: ['pii' as const],
    review: { needsReview: false, reasons: [] },
    network: null,
    endpoints: [
      {
        id: 'ep-1',
        method: 'GET' as const,
        transport: 'https' as const,
        url: 'https://api.okta.com/v1/users',
        template: false,
        dataClass: 'pii' as const,
        lastSeen: '2026-07-01T00:00:00.000Z',
        callSiteCount: 1,
        sites: [],
      },
    ],
  };
}

function render(props: Partial<Parameters<typeof DataSharesClient>[0]> = {}) {
  return renderToStaticMarkup(
    createElement(
      NavigationTransitionProvider,
      null,
      createElement(DataSharesClient, {
        q: '',
        groups: [],
        review: [],
        destination: null,
        selectedDest: null,
        selectedEndpoint: null,
        renderedAt: Date.parse('2026-08-01T00:30:00.000Z'),
        ...props,
      }),
    ),
  );
}

describe('DataSharesClient', () => {
  it('renders the empty state when there are no groups', () => {
    const html = render();
    expect(html).toContain('No outbound data shares detected');
  });

  it('renders a search-empty message once a query is active', () => {
    const html = render({ q: 'nonexistent' });
    expect(html).toContain('No destinations match');
  });

  it('renders the kind tabs and table once groups are present', () => {
    const html = render({ groups: [group('provider', 1), group('ip', 3)] });
    expect(html).toContain('Providers');
    expect(html).toContain('Raw IP addresses');
    expect(html).toContain('Destination (provider)');
  });

  it('renders the needs-review strip once review items are present', () => {
    const html = render({ groups: [group('provider', 1)], review: [reviewItem()] });
    expect(html).toContain('Needs review');
  });

  // The queue is selected on trust rather than kind, so its count spans every
  // tab while the table under it shows one. These three pin the qualifier to
  // the case where those two really can disagree on screen.
  it('qualifies the review count once more than one kind tab exists', () => {
    const html = render({
      groups: [group('provider', 1), group('ip', 3)],
      review: [reviewItem()],
    });
    expect(html).toContain('All destinations');
  });

  it('omits the qualifier when a single group means nothing is narrowed', () => {
    const html = render({ groups: [group('provider', 1)], review: [reviewItem()] });
    expect(html).toContain('Needs review');
    expect(html).not.toContain('All destinations');
  });

  // Not a qualifier case at all: the server sends an empty queue while a term
  // is set (page.tsx), so the strip is absent rather than showing a count over
  // filtered rows. Asserted here because the opposite was believed during
  // review, and nothing else in the tree pins it.
  it('shows no strip at all while a search term is active', () => {
    const html = render({
      q: 'nonexistent',
      groups: [group('provider', 1), group('ip', 3)],
      review: [],
    });
    expect(html).not.toContain('Needs review');
    expect(html).not.toContain('All destinations');
  });

  // The Sheet's own content never appears in this output: ui-kit's Sheet is
  // built on @radix-ui/react-dialog, whose Portal only mounts once a
  // useLayoutEffect flips `mounted` — a client-only effect renderToStaticMarkup
  // never runs, so the Portal (and everything inside it: the detail view, the
  // needs-review list, every handler wired to them) renders as null server-side
  // regardless of `drawerOpen`. These two cases still exercise the derivations
  // that DO run outside the Portal (`drawerOpen`, `selectedEp`) by asserting the
  // render completes without throwing for both a resolved and an unresolved
  // selection — interactions.test.ts covers the handlers' own logic directly.
  it('does not throw when a selected destination resolves', () => {
    expect(() =>
      render({
        groups: [group('provider', 1)],
        selectedDest: 'dest-provider',
        destination: destinationDetail(),
      }),
    ).not.toThrow();
  });

  it('does not throw when the selected destination no longer resolves', () => {
    expect(() =>
      render({
        groups: [group('provider', 1)],
        selectedDest: 'dest-gone',
        destination: null,
      }),
    ).not.toThrow();
  });

  // The search box. This page's copy of it had drifted from the one the
  // enterprise dashboard renders on all three of the decisions a field makes,
  // and the drift was invisible: the package that pins every other field in the
  // product (@akasecurity/dashboard-ui's theme/field-boundary.test.ts) reads its
  // own src/ and cannot see this file.
  //
  // Asserted on the RENDERED class string rather than on the source, because the
  // three decisions have two owners now — the edge and the fill are this page's
  // to choose, the focus ring is the shared field's — and only the composed
  // output shows them arriving together.
  describe('the search box', () => {
    /**
     * The ONE class attribute belonging to the search field's own wrapper, found
     * by walking back from the input that carries its accessible name.
     *
     * Joining every class attribute on the page would have been enough to go red
     * today, and wrong: the assertions below would then match a fragment on any
     * card, chip or button this page grows later, while the field itself sat on
     * the wrong edge. The subject has to be the element under test.
     */
    const fieldClasses = (html: string): string[] => {
      const at = html.indexOf('aria-label="Search data shares"');
      expect(at, "no element carries the search box's accessible name").toBeGreaterThan(-1);
      // The wrapper is the nearest `<div class="…">` BEFORE that input: the
      // input's own class attribute follows its aria-label, the wrapper's
      // precedes it. `<div` rather than any element because the leading search
      // glyph is an `<svg class="size-4 …">` sitting between the two, and a
      // match on any tag picks the GLYPH — which reads as a red test for the
      // right reason while actually measuring the wrong element.
      const wrappers = [...html.slice(0, at).matchAll(/<div[^>]*\sclass="([^"]*)"/g)];
      const last = wrappers.at(-1);
      expect(last, 'the search input is not inside a classed wrapper').toBeDefined();
      // Split into TOKENS rather than returned as one string: `toContain` on a
      // string is a substring test, and `bg-surface` is a PREFIX of
      // `bg-surface-2` — so a field that declared the wrong surface satisfied a
      // `bg-surface` assertion outright. On an array `toContain` is exact.
      return (last?.[1] ?? '').split(/\s+/).filter(Boolean);
    };

    // `border-border` measures 1.26:1 light and 1.42:1 dark, under the 3:1 a
    // control boundary is asked for; `bg-surface-2` is the canvas's own fill in
    // light, so a field carrying it has no fill of its own. This box sat on both.
    it('carries an edge that clears 3:1 and a fill off the page canvas', () => {
      const classes = fieldClasses(render());
      expect(classes).toContain('border-border-field');
      expect(classes).not.toContain('border-border');
      // `--color-canvas` and `--color-surface-2` are the same hex in light, so
      // this is the one fill a canvas-level field must not take.
      expect(classes).toContain('bg-surface');
      expect(classes).not.toContain('bg-surface-2');
    });

    // The input suppresses its own outline, so without this the box showed
    // nothing at all on focus — not a weak indicator, none.
    it('keeps a focus indicator', () => {
      const classes = fieldClasses(render());
      for (const token of [
        'focus-within:border-primary',
        'focus-within:ring-2',
        'focus-within:ring-primary/40',
      ]) {
        expect(classes).toContain(token);
      }
    });

    // Both directions: a control that is always there is as wrong as one that
    // never is, and the empty case is the only one that can show the button's
    // presence is a function of the term at all.
    it('offers nothing to clear while there is no term', () => {
      expect(render()).not.toContain('Clear search');
    });

    it('offers a clear button once a term is active', () => {
      expect(render({ q: 'okta' })).toContain('aria-label="Clear search"');
    });
  });
});
