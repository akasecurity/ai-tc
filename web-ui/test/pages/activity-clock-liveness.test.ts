// @vitest-environment jsdom
//
// The LIVENESS half of the activity route's clock, in the same shape
// exceptions-clock-liveness.test.ts pins for its own routes — see that file's
// header for why a static (renderToStaticMarkup) suite structurally cannot
// prove this: under the server renderer `useSyncExternalStore` reads
// `getServerSnapshot`, which is `() => renderedAt` either way `now` is wired,
// so `useRenderClock(renderedAt)` and a bare `renderedAt` emit identical
// markup there.
//
// That gap is not theoretical here either: `ActivityClient` shipped a full
// review round with `renderedAt` threaded straight to `SessionListView` and
// into `detailProps` with no `useRenderClock` call at all. Every existing
// suite in this repo stayed green — the hydration mismatch this PR fixes was
// gone, so nothing caught that the label had gone from "wrong once, then
// self-correcting" to "correct once, then frozen for the life of the tab".
// Closing it needs a real client render.
import { CLOCK_TICK_MS } from '@akasecurity/dashboard-ui';
import type { ActivitySessionSummary } from '@akasecurity/schema';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('next/navigation', () => ({
  usePathname: () => '/activity',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { ActivityClient } = await import('../../app/(app)/activity/ActivityClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const RENDERED_AT = new Date(2026, 6, 5, 22, 45).getTime();
const HALF_HOUR = 30 * 60 * 1000;

function session(over: Partial<ActivitySessionSummary> = {}): ActivitySessionSummary {
  return {
    id: 'sess-1',
    harness: 'claudecode',
    title: 'Refactor auth',
    project: 'api',
    repo: 'acme/api',
    branches: ['main'],
    startedAt: new Date(RENDERED_AT - HALF_HOUR).toISOString(),
    endedAt: null,
    status: 'active',
    turns: 4,
    findings: 0,
    shares: 0,
    ...over,
  };
}

function route(sessions: ActivitySessionSummary[]) {
  return createElement(
    NavigationTransitionProvider,
    null,
    createElement(ActivityClient, {
      sessions,
      detail: null,
      tokenReport: null,
      liveFindings: null,
      q: '',
      harness: [],
      harnessOptions: [],
      range: '30d',
      selectedId: '',
      hasMore: false,
      emptyCount: 0,
      showEmpty: false,
      expanded: false,
      renderedAt: RENDERED_AT,
    }),
  );
}

function mount(element: ReturnType<typeof createElement>): HTMLElement {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  act(() => {
    root.render(element);
  });
  return container;
}

describe('the activity clock keeps moving after hydration', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // Deliberately ON the server instant, as the exceptions suite does: the
    // mount-time catch-up is then a no-op, so nothing below can pass because
    // of it — only the interval firing can move these labels.
    vi.setSystemTime(RENDERED_AT);
    (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
      true;
  });
  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  it('advances an active session\'s "· live" duration chip without a navigation', () => {
    const container = mount(route([session()]));

    expect(container.textContent).toContain('30m · live');

    act(() => {
      vi.advanceTimersByTime(HALF_HOUR);
    });

    // Only the interval can have moved this: nothing navigated or re-rendered
    // the tree from outside, and the session's own endedAt is still null.
    expect(container.textContent).toContain('1h 0m · live');
    expect(container.textContent).not.toContain('30m · live');
  });

  it('relabels the day heading once the clock crosses local midnight, without a navigation', () => {
    // The session sits just before midnight; the server render is captured at
    // the same instant, so the heading starts as Today.
    const container = mount(
      route([
        session({
          startedAt: new Date(RENDERED_AT).toISOString(),
          endedAt: new Date(RENDERED_AT).toISOString(),
          status: 'completed',
        }),
      ]),
    );

    expect(container.textContent).toContain('Today');
    expect(container.textContent).not.toContain('Yesterday');

    act(() => {
      // 75 minutes: from 22:45 to 00:00 (75m) crosses midnight.
      vi.advanceTimersByTime(75 * 60 * 1000);
    });

    expect(container.textContent).toContain('Yesterday');
  });

  it('drives the duration chip off the shared tick length', () => {
    // Placed just inside the first tick, the way the exceptions suite's third
    // case is: a wiring site that hard-coded its own interval, or dropped the
    // hook back to a bare renderedAt, is caught rather than covered by the
    // generous half-hour the case above advances.
    const container = mount(
      route([session({ startedAt: new Date(RENDERED_AT - 60_000).toISOString() })]),
    );

    expect(container.textContent).toContain('1m · live');

    act(() => {
      vi.advanceTimersByTime(CLOCK_TICK_MS);
    });

    expect(container.textContent).not.toContain('1m · live');
  });
});
