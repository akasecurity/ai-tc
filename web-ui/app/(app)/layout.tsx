import type { ReactNode } from 'react';

import { AppShell } from '../components/AppShell';
import { NavigationTransitionProvider } from '../components/NavigationTransition';

// Route-group layout: every page under (app) renders inside the shell. The group
// parens keep the URLs flat (/security, /findings, …). The transition provider
// wraps the shell so the progress bar in the shell and the dimming in each
// page's client read the same pending flag.
export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <NavigationTransitionProvider>
      <AppShell>{children}</AppShell>
    </NavigationTransitionProvider>
  );
}
