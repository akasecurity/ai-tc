import type { ReactNode } from 'react';

import { AppShell } from '../components/AppShell';

// Route-group layout: every page under (app) renders inside the shell. The group
// parens keep the URLs flat (/security, /findings, …).
export default function AppLayout({ children }: { children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
