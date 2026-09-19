import type { ReactNode } from 'react';

import { AppShell } from '../components/AppShell';
import { NavigationTransitionProvider } from '../components/NavigationTransition';
import { StoreSkewNotice } from '../components/StoreSkewNotice';
import { storeVersionSkew } from '../lib/db';

// Route-group layout: every page under (app) renders inside the shell. The group
// parens keep the URLs flat (/security, /findings, …). The transition provider
// wraps the shell so the progress bar in the shell and the dimming in each
// page's client read the same pending flag.
//
// The skew check sits HERE rather than in each page because it is the one store
// failure a page cannot report for itself: a throw from `db()` reaches the error
// boundary, which shows a digest and no cause. Checking once, above the pages,
// turns that into a notice naming the remedy.
//
// What it costs depends on the store, and only the healthy path is free. There,
// `db()` memoises its handle, so this is the same open the page below was going
// to perform. On a skew store the page segment still renders: the App Router
// renders it IN PARALLEL with this layout, whether or not `children` is placed,
// so the page's own `db()` runs, finds nothing memoised (a FAILED open memoises
// nothing) and throws a second `StoreAheadOfBuildError` that Next logs with a
// digest. The browser still gets this notice with a 200, and the error boundary
// never mounts because the slot that would have held the page is unused — but
// the server log stays loud until the update, which is the price of saying what
// happened instead of showing a digest.
//
// Only SKEW short-circuits. Every other store failure returns null here and
// still reaches the boundary from the page, so a genuinely unreadable store is
// reported as one.
export default function AppLayout({ children }: { children: ReactNode }) {
  const skew = storeVersionSkew();
  return (
    <NavigationTransitionProvider>
      <AppShell>{skew === null ? children : <StoreSkewNotice skew={skew} />}</AppShell>
    </NavigationTransitionProvider>
  );
}
