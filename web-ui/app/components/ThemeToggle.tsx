'use client';

import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@akasecurity/ui-kit';
import { useEffect, useSyncExternalStore } from 'react';

import {
  applyTheme,
  isThemePreference,
  prefersDark,
  readStoredPreference,
  serverPreference,
  serverPrefersDark,
  storePreference,
  subscribePreference,
  subscribeSystemTheme,
  THEME_PREFERENCES,
  type ThemePreference,
} from '../lib/theme.ts';

const LABELS: Record<ThemePreference, string> = {
  light: 'Light',
  dark: 'Dark',
  system: 'System',
};

function SunIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable={false}
      className={className}
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
    </svg>
  );
}

function MoonIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable={false}
      className={className}
    >
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
    </svg>
  );
}

/**
 * Topbar theme picker.
 *
 * localStorage and the OS media query are external stores, so they are read
 * through useSyncExternalStore rather than copied into state by an effect: the
 * server snapshot renders the default, and React swaps in the real value on
 * hydration. The inline script in the root layout has already applied the class,
 * so nothing flashes while that happens.
 */
export function ThemeToggle() {
  const preference = useSyncExternalStore(
    subscribePreference,
    readStoredPreference,
    serverPreference,
  );
  const systemDark = useSyncExternalStore(subscribeSystemTheme, prefersDark, serverPrefersDark);

  const resolved: 'light' | 'dark' =
    preference === 'system' ? (systemDark ? 'dark' : 'light') : preference;

  // Writing the class is a DOM side effect, not state — this keeps <html> in sync
  // when the OS flips while the picker is on 'system'.
  useEffect(() => {
    applyTheme(resolved);
  }, [resolved]);

  const choose = (value: string) => {
    if (!isThemePreference(value)) return;
    storePreference(value);
  };

  const Icon = resolved === 'dark' ? MoonIcon : SunIcon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          tone="neutral"
          size="icon"
          aria-label={`Theme: ${LABELS[preference]}`}
        >
          <Icon className="size-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuRadioGroup value={preference} onValueChange={choose}>
          {THEME_PREFERENCES.map((value) => (
            <DropdownMenuRadioItem key={value} value={value}>
              {LABELS[value]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
