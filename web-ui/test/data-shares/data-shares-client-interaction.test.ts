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

vi.mock('next/navigation', () => ({
  usePathname: () => '/data-shares',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { DataSharesClient } = await import('../../app/(app)/data-shares/DataSharesClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

/** A single provider group carrying two hosts that share `providerId: 'github'`. */
function twoHostProviderGroup() {
  const host = (id: string, name: string, hostname: string) => ({
    id,
    kind: 'provider' as const,
    name,
    host: hostname,
    providerId: 'github',
    category: 'Dev tools',
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
  });
  return {
    kind: 'provider' as const,
    total: 2,
    items: [
      host('dest-github-1', 'GitHub', 'api.github.com'),
      host('dest-github-2', 'GitHub Raw', 'raw.githubusercontent.com'),
    ],
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

  it('leaves the provider row folded once a different, unrelated host is selected and closed', () => {
    const group = twoHostProviderGroup();

    mount({ groups: [group], selectedDest: null });
    expect(container.textContent).not.toContain('api.github.com');
    expect(container.textContent).not.toContain('raw.githubusercontent.com');
    expect(container.textContent).toContain('2 hosts');
  });
});
