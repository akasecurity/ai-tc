// @vitest-environment jsdom
//
// The LIVENESS half of the exceptions clock, pinned at the two wiring sites
// that call the hook.
//
// The sibling suites next door render through `renderToStaticMarkup`, and under
// the server renderer `useSyncExternalStore` reads `getServerSnapshot` — which
// is `() => renderedAt`. So `useRenderClock(renderedAt)` and a bare
// `renderedAt` emit byte-identical markup there, and every static assertion in
// this directory passes either way. Those suites pin that the instant REACHES
// the views; nothing in them can pin that the clock still moves afterwards.
//
// That gap is not theoretical: replacing both `const now = useRenderClock(...)`
// with `const now = renderedAt` left all of web-ui and dashboard-ui green while
// restoring the frozen-clock bug on both routes.
//
// Closing it needs a real client render, so this file opts into jsdom per-file
// — the same opt-in dashboard-ui uses for the hook's own suite, rather than
// paying for a DOM across every suite in the package.
//
// Each case starts the ambient clock ON the server instant, so the mount-time
// catch-up changes nothing and the assertion can only be satisfied by the
// INTERVAL having fired. A frozen wiring site renders the same thing forever.
import { CLOCK_TICK_MS } from '@akasecurity/dashboard-ui';
import type { BlockedDetectionDescriptor, DetectionException } from '@akasecurity/schema';
import { toExceptionDescriptor } from '@akasecurity/schema';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('next/navigation', () => ({
  usePathname: () => '/exceptions',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { ExceptionsClient } = await import('../../app/(app)/exceptions/ExceptionsClient.tsx');
const { ExceptionDetailClient } =
  await import('../../app/(app)/exceptions/[id]/ExceptionDetailClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const RENDERED_AT = Date.parse('2026-08-01T00:30:00.000Z');
const HALF_HOUR = 30 * 60 * 1000;

function blockedRow(): BlockedDetectionDescriptor {
  return {
    reference: 'blk-fresh',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    keyVersion: 4,
    maskedValue: 'AKIA****************',
    sessionId: null,
    repo: 'acme/api',
    blockedAt: '2026-08-01T00:00:00.000Z',
  };
}

function exceptionRow(overrides: Partial<DetectionException>) {
  return toExceptionDescriptor({
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: 4,
    maskedValue: 'A****Z',
    capability: 'suppress',
    scope: 'temporary',
    expiresAt: null,
    maxUses: null,
    useCount: 0,
    lastUsedAt: null,
    justification: 'test fixture',
    conditions: null,
    createdBy: 'tester',
    createdVia: 'web-add',
    createdAt: '2026-08-01T00:00:00.000Z',
    updatedAt: '2026-08-01T00:00:00.000Z',
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    ...overrides,
  });
}

/** Mounts into a real root and returns the live container. */
function mount(element: ReturnType<typeof createElement>): HTMLElement {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  act(() => {
    root.render(element);
  });
  return container;
}

describe('the exceptions clock keeps moving after hydration', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // Deliberately ON the server instant: the catch-up on subscribe is then a
    // no-op, so nothing below can pass because of it.
    vi.setSystemTime(RENDERED_AT);
    (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
      true;
  });
  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  it('ages the blocked ledger on the list route without a navigation', () => {
    const container = mount(
      createElement(
        NavigationTransitionProvider,
        null,
        createElement(ExceptionsClient, {
          items: [],
          blocked: [blockedRow()],
          includeTerminal: false,
          blockedWindow: '30m' as const,
          keyState: { status: 'present', version: 4 },
          activePermanent: [],
          approvableBlocked: 1,
          renderedAt: RENDERED_AT,
        }),
      ),
    );

    expect(container.textContent).toContain('30 minutes ago');

    act(() => {
      vi.advanceTimersByTime(HALF_HOUR);
    });

    // Only the interval can have moved this: the clock started on the server
    // instant, and nothing navigated or re-rendered the tree from outside.
    expect(container.textContent).toContain('1 hour ago');
    expect(container.textContent).not.toContain('30 minutes ago');
  });

  it('lets a grant expire out from under the detail route, taking the revoke form', () => {
    // The strongest form of this: on the detail route the clock does not merely
    // relabel, it decides whether the revoke form is rendered at all. A frozen
    // clock leaves someone looking at a live-looking Revoke for an expired
    // grant, which the server would refuse.
    const container = mount(
      createElement(ExceptionDetailClient, {
        exception: exceptionRow({ expiresAt: '2026-08-01T00:45:00.000Z' }),
        renderedAt: RENDERED_AT,
      }),
    );

    expect(container.textContent).toContain('active');
    expect(container.textContent).not.toContain('expired');
    expect(container.textContent).toContain('Revoke this grant');

    act(() => {
      vi.advanceTimersByTime(HALF_HOUR);
    });

    expect(container.textContent).toContain('expired');
    expect(container.textContent).not.toContain('Revoke this grant');
  });

  it('drives both routes off the shared tick length', () => {
    // A single tick is enough to move the detail route's state, so the wiring
    // is bound to CLOCK_TICK_MS rather than to whatever interval a caller might
    // have hard-coded. Expiry sits inside the first tick.
    const container = mount(
      createElement(ExceptionDetailClient, {
        exception: exceptionRow({ expiresAt: new Date(RENDERED_AT + 1000).toISOString() }),
        renderedAt: RENDERED_AT,
      }),
    );

    expect(container.textContent).toContain('active');
    expect(container.textContent).not.toContain('expired');

    act(() => {
      vi.advanceTimersByTime(CLOCK_TICK_MS);
    });

    expect(container.textContent).toContain('expired');
  });
});
