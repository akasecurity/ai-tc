// Self-hosted fonts → the --font-ui/display/mono CSS vars in @akasecurity/ui-kit theme.css
// resolve (same fonts the Vite dashboard uses).
import '@fontsource-variable/inter';
import '@fontsource-variable/space-grotesk';
import '@fontsource-variable/jetbrains-mono';
import './globals.css';

import { THEME_INIT_SCRIPT } from '@akasecurity/dashboard-ui/theme';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
  title: {
    // Per-page titles fill %s; pages without their own title fall back to `default`.
    template: '%s · AI Traffic Control',
    default: 'AI Traffic Control',
  },
  description:
    'AI Traffic Control (ai-tc) by AKA Security — local-first security dashboard (open source).',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  // suppressHydrationWarning: the init script sets the `dark` class on <html> before
  // React hydrates, so the client's class attribute intentionally differs from the
  // server-rendered one. It is scoped to <html> itself and does not reach children.
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Runs before first paint so a dark-mode load never flashes light. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
