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
// turns that into a notice naming the remedy. It costs a healthy dashboard
// nothing — `db()` memoises its handle, so this is the same open the page below
// was going to perform.
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
