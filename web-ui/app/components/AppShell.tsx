'use client';

import type { IconComponent } from '@akasecurity/dashboard-ui';
import { cn } from '@akasecurity/ui-kit';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';

import {
  ActivityIcon,
  AkaLogo,
  ExternalShareIcon,
  KeyIcon,
  LayersIcon,
  ListIcon,
  PolicyIcon,
  RefreshIcon,
  SearchIcon,
  SettingsIcon,
  ShieldCheckIcon,
} from './icons.tsx';

// Sidebar + topbar shell layout, built for Next.js (next/link + usePathname).
// No auth/user-card/sign-out; icons stay inline (the app
// pulls in no svgr). The topbar carries no search, notifications, or recommended
// actions. Items without an href are not yet routed and render as inert rows.
interface NavItem {
  label: string;
  icon: IconComponent;
  href?: string;
}

const NAV: NavItem[] = [
  { label: 'Security', icon: ShieldCheckIcon, href: '/security' },
  { label: 'Findings', icon: ListIcon, href: '/findings' },
  { label: 'Inventory', icon: LayersIcon, href: '/inventory' },
  { label: 'Data Shares', icon: ExternalShareIcon, href: '/data-shares' },
  { label: 'Activity', icon: ActivityIcon, href: '/activity' },
  { label: 'Detections', icon: ListIcon, href: '/detections' },
  { label: 'Policies', icon: PolicyIcon, href: '/policies' },
  { label: 'Exceptions', icon: KeyIcon, href: '/exceptions' },
  { label: 'Scan', icon: SearchIcon, href: '/scan' },
  { label: 'Updates', icon: RefreshIcon, href: '/updates' },
  { label: 'Settings', icon: SettingsIcon, href: '/settings' },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  return (
    <div className="flex h-screen overflow-hidden bg-canvas">
      <Sidebar pathname={pathname} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}

function Sidebar({ pathname }: { pathname: string }) {
  return (
    <aside className="flex w-62 flex-col border-r border-border bg-surface shrink-0">
      <div className="flex h-16 items-center border-b border-text/6 px-5">
        <AkaLogo aria-label="AKA" className="h-8 w-auto text-text" />
      </div>
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-3 py-3.5">
        {NAV.map((item) => (
          <NavRow
            key={item.label}
            item={item}
            active={
              item.href !== undefined &&
              (pathname === item.href || pathname.startsWith(`${item.href}/`))
            }
          />
        ))}
      </nav>
    </aside>
  );
}

function NavRow({ item, active }: { item: NavItem; active: boolean }) {
  const Icon = item.icon;

  const className = cn(
    'flex w-full items-center gap-3 rounded-lg px-3 h-10 text-left text-sm group font-medium transition-colors cursor-pointer',
    active
      ? 'bg-primary-tint text-primary font-semibold'
      : 'text-text-2 hover:bg-surface-2 hover:text-text',
  );

  const content = (
    <>
      <Icon
        aria-hidden
        focusable={false}
        className={cn(
          'size-4 shrink-0',
          active ? 'text-primary' : 'text-text-3 group-hover:text-text-2',
        )}
      />
      <span className="flex-1">{item.label}</span>
    </>
  );

  if (item.href) {
    return (
      <Link href={item.href} aria-current={active ? 'page' : undefined} className={className}>
        {content}
      </Link>
    );
  }

  return (
    <button type="button" aria-current={active ? 'page' : undefined} className={className}>
      {content}
    </button>
  );
}

function TopBar() {
  return (
    <header className="flex items-center gap-4 border-b border-border bg-surface px-6 h-16">
      <div className="ml-auto flex items-center gap-2"></div>
    </header>
  );
}
