// Self-hosted fonts → the --font-ui/display/mono CSS vars in @akasecurity/ui-kit theme.css
// resolve (same fonts the Vite dashboard uses).
import '@fontsource-variable/inter';
import '@fontsource-variable/space-grotesk';
import '@fontsource-variable/jetbrains-mono';
import './globals.css';

import type { Metadata } from 'next';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
  title: 'AI Traffic Control',
  description:
    'AI Traffic Control (ai-tc) by AKA Security — local-first security dashboard (open source).',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
