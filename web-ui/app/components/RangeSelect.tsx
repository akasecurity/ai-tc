'use client';

import { type TimeRange, TimeRangeSelect } from '@akasecurity/dashboard-ui';
import { cn } from '@akasecurity/ui-kit';
import { usePathname, useSearchParams } from 'next/navigation';

import { useNavigationTransition } from './NavigationTransition';

// Client wrapper that drives the security range off the URL: picking a range
// pushes ?range=… so the Server Component re-fetches db.security.* for it. The
// picker dims while that render is in flight — the range control sits in the
// page head and cannot dim the cards it drives, so this plus the shell's
// progress bar is the feedback a range change gets.
export function RangeSelect({ value }: { value: TimeRange }) {
  const pathname = usePathname();
  const params = useSearchParams();
  const { isPending, push } = useNavigationTransition();

  return (
    <span className={cn('transition-opacity duration-150', isPending && 'opacity-60')}>
      <TimeRangeSelect
        value={value}
        onChange={(next) => {
          const sp = new URLSearchParams(params.toString());
          sp.set('range', next);
          push(`${pathname}?${sp.toString()}`);
        }}
      />
    </span>
  );
}
