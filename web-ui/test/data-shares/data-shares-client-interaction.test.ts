// @vitest-environment jsdom
//
// What this suite drives, which the sibling static-render suite cannot see:
// renderToStaticMarkup runs no effects, so a pin that has to survive past the
// render that set it — this component's own comment on the point — is
// invisible there. The environment is opted into per file, matching this
// repo's other jsdom-only DOM suites.
import type React from 'react';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { twoHostProviderGroup } from './fixtures.ts';

vi.mock('next/navigation', () => ({
  usePathname: () => '/data-shares',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { DataSharesClient } = await import('../../app/(app)/data-shares/DataSharesClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

/** A plain, non-provider destination — unrelated to any provider fold. */
function externalDestination() {
  return {
    id: 'dest-external-1',
    kind: 'external' as const,
    name: 'Acme Partner',
    host: 'api.acme-partner.com',
    providerId: null,
    category: 'External domain',
    trust: 'unverified' as const,
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
  };
}

/** A provider destination that is the only host of its providerId — never folded. */
function loneProviderHost() {
  return {
    id: 'dest-solo-1',
    kind: 'provider' as const,
    name: 'Okta',
    host: 'okta.com',
    providerId: 'okta',
    category: 'Identity',
    trust: 'recognized' as const,
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
  };
}

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

function mount(over: Record<string, unknown> = {}): void {
  act(() => {
    root.render(
      createElement(
        NavigationTransitionProvider,
        null,
        createElement(DataSharesClient as unknown as React.FC<Record<string, unknown>>, {
          q: '',
          groups: [],
          review: [],
          destination: null,
          selectedDest: null,
          selectedEndpoint: null,
          renderedAt: Date.parse('2026-08-01T00:30:00.000Z'),
          ...over,
        }),
      ),
    );
  });
}

describe('DataSharesClient — provider row stays open past a folded-host selection', () => {
  it('keeps the provider row expanded once the drawer closes on a folded host', () => {
    const group = twoHostProviderGroup();

    // Loading `?dest=…` on a folded host: the drawer is open, so the row shows
    // via `holdsSelection` regardless of the fix under test.
    mount({ groups: [group], selectedDest: 'dest-github-1' });
    expect(container.textContent).toContain('api.github.com');
    expect(container.textContent).toContain('raw.githubusercontent.com');

    // The drawer closes (the server sends `selectedDest: null`, as it does
    // once `dest` drops out of the URL) — same mounted instance, so its
    // `expanded` state survives the prop change.
    mount({ groups: [group], selectedDest: null });
    expect(container.textContent).toContain('api.github.com');
    expect(container.textContent).toContain('raw.githubusercontent.com');
  });

  it('stays folded once a different, unrelated host is selected and closed', () => {
    const providerGroup = twoHostProviderGroup();
    const externalGroup = { kind: 'external' as const, total: 1, items: [externalDestination()] };
    const groups = [providerGroup, externalGroup];

    // Select an unrelated, non-provider destination — foldedProviderRowId
    // returns null for it, so the pin must write no provider key. (It lives
    // in the 'external' tab, so it renders in the drawer/tab strip rather
    // than the 'provider' tab this render is showing — that is not what this
    // case is checking.)
    mount({ groups, selectedDest: 'dest-external-1' });

    // Close it. If the pin had written a key anyway, the unrelated selection
    // would have left the provider group open too.
    mount({ groups, selectedDest: null });
    expect(container.textContent).not.toContain('api.github.com');
    expect(container.textContent).not.toContain('raw.githubusercontent.com');
    expect(container.textContent).toContain('2 hosts');
  });

  it('writes no provider key when the selection is the lone host of an unfolded provider', () => {
    const providerGroup = { kind: 'provider' as const, total: 1, items: [loneProviderHost()] };

    // A lone host is never folded (groupByProvider leaves it a plain row), so
    // foldedProviderRowId returns null and there is no group id for the pin
    // to write. Select it, close it, and confirm it renders as a plain row
    // throughout rather than ever picking up a "hosts" summary.
    mount({ groups: [providerGroup], selectedDest: 'dest-solo-1' });
    expect(container.textContent).toContain('Okta');
    expect(container.textContent).not.toContain('hosts');

    mount({ groups: [providerGroup], selectedDest: null });
    expect(container.textContent).toContain('Okta');
    expect(container.textContent).not.toContain('hosts');
  });
});
