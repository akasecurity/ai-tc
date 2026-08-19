'use client';

import { useRouter } from 'next/navigation';
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useTransition,
} from 'react';

/**
 * One navigation transition shared by every URL push on a page.
 *
 * Filter, search, range and selection changes all push a new URL so the Server
 * Component re-queries the local store. Next renders that in a transition, which
 * keeps the current screen mounted until the new one is ready — so without a
 * pending signal the page looks frozen for the length of the render. Wrapping
 * the push in `startTransition` here exposes that window as `isPending`, which
 * the list clients use to dim their results region and the shell uses to show a
 * progress bar.
 *
 * A route-level loading.tsx does not cover this case: an already-revealed
 * Suspense boundary is not re-shown for a same-route searchParams change. The
 * two mechanisms are complementary — loading.tsx covers arriving at a route,
 * this covers changing what a route shows.
 *
 * A dimmed region stays INTERACTIVE by choice. Blocking input would mean a
 * navigation that resolves in a few milliseconds swallowing a click that landed
 * during it, which reads as a broken control; a click that lands mid-navigation
 * instead queues a second push, which simply supersedes the first.
 */
interface NavigationTransition {
  isPending: boolean;
  push: (url: string) => void;
  /**
   * Same transition, but overwriting the current history entry instead of adding
   * one. For a state change that undoes the entry it is reverting — dismissing a
   * panel a push opened — where a second entry would put the dismissed state on
   * the Back path and re-open it.
   */
  replace: (url: string) => void;
}

const NavigationTransitionContext = createContext<NavigationTransition | null>(null);

export function NavigationTransitionProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  const push = useCallback(
    (url: string) => {
      startTransition(() => {
        router.push(url);
      });
    },
    [router],
  );

  const replace = useCallback(
    (url: string) => {
      startTransition(() => {
        router.replace(url);
      });
    },
    [router],
  );

  const value = useMemo(() => ({ isPending, push, replace }), [isPending, push, replace]);

  return (
    <NavigationTransitionContext.Provider value={value}>
      {children}
    </NavigationTransitionContext.Provider>
  );
}

/**
 * The shared transition. Throws outside the provider rather than degrading: every
 * consumer renders under (app)/layout.tsx, so a missing provider is a wiring
 * mistake, and a silent passthrough would hide it as a page that simply never
 * reports pending.
 */
export function useNavigationTransition(): NavigationTransition {
  const ctx = useContext(NavigationTransitionContext);
  if (ctx === null) {
    throw new Error('useNavigationTransition must be used within NavigationTransitionProvider');
  }
  return ctx;
}

// How long a navigation must stay in flight before the progress bar mounts. The
// bar is GATED ON A TIMER rather than faded in by the animation: the element
// carries role="progressbar", so assistive tech announces it the moment it
// enters the DOM, and an opacity delay would leave every three-millisecond
// navigation announcing "Loading" to a screen reader while showing nothing to
// everyone else. Mounting late means the two agree.
const PROGRESS_APPEAR_MS = 150;

/**
 * Top-edge progress bar for an in-flight navigation, mounted only once the
 * navigation has outlived PROGRESS_APPEAR_MS.
 */
export function NavigationProgressBar() {
  const { isPending } = useNavigationTransition();
  // Only the timer sets this, and the cleanup clears it when the navigation
  // ends — so the next navigation starts from false and waits out its own delay
  // rather than inheriting the previous one's.
  const [elapsed, setElapsed] = useState(false);

  useEffect(() => {
    if (!isPending) return;
    const handle = setTimeout(() => {
      setElapsed(true);
    }, PROGRESS_APPEAR_MS);
    return () => {
      clearTimeout(handle);
      setElapsed(false);
    };
  }, [isPending]);

  if (!isPending || !elapsed) return null;
  return (
    // aria-busy belongs on the region being updated, not on the indicator — the
    // list clients carry it on their results regions.
    <div
      role="progressbar"
      aria-label="Loading"
      className="pointer-events-none absolute inset-x-0 top-0 z-50 h-0.5 overflow-hidden"
    >
      <div className="h-full w-full origin-left animate-nav-progress bg-primary-solid" />
    </div>
  );
}
