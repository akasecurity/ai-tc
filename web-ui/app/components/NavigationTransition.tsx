'use client';

import { useRouter } from 'next/navigation';
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
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
 */
interface NavigationTransition {
  isPending: boolean;
  push: (url: string) => void;
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

  const value = useMemo(() => ({ isPending, push }), [isPending, push]);

  return (
    <NavigationTransitionContext.Provider value={value}>
      {children}
    </NavigationTransitionContext.Provider>
  );
}

/**
 * The shared transition, or a passthrough when rendered outside the provider —
 * a component mounted without the shell still navigates, it just reports no
 * pending state rather than throwing.
 */
export function useNavigationTransition(): NavigationTransition {
  const ctx = useContext(NavigationTransitionContext);
  const router = useRouter();
  const fallbackPush = useCallback(
    (url: string) => {
      router.push(url);
    },
    [router],
  );
  const fallback = useMemo(() => ({ isPending: false, push: fallbackPush }), [fallbackPush]);
  return ctx ?? fallback;
}

/**
 * Top-edge progress bar for an in-flight navigation. Appears only after the
 * render has run past `appear-delay`, so the many navigations that resolve in a
 * few milliseconds never flash it.
 */
export function NavigationProgressBar() {
  const { isPending } = useNavigationTransition();
  if (!isPending) return null;
  return (
    <div
      role="progressbar"
      aria-label="Loading"
      aria-busy="true"
      className="pointer-events-none absolute inset-x-0 top-0 z-50 h-0.5 overflow-hidden"
    >
      <div className="h-full w-full origin-left animate-nav-progress bg-primary-solid" />
    </div>
  );
}
