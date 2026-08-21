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
});
