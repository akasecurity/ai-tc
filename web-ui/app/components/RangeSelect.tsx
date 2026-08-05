'use client';

import { type TimeRange, TimeRangeSelect } from '@akasecurity/dashboard-ui';
import { cn } from '@akasecurity/ui-kit';
import { usePathname, useSearchParams } from 'next/navigation';

import { useNavigationTransition } from './NavigationTransition';

// Client wrapper that drives the security range off the URL: picking a range
// pushes ?range=… so the Server Component re-fetches db.security.* for it. The
// picker is ringed while that render is in flight — the range control sits in
// the page head and cannot mark the cards it drives, so this plus the shell's
// progress bar is the feedback a range change gets. It rings rather than fades
// for the same reason the page regions do: fading composites the control's own
// label toward the canvas, and the text tokens have no contrast headroom to
// spend. The ring sits outside the control's box so it does not double up on
// the select's own border.
export function RangeSelect({ value }: { value: TimeRange }) {
  const pathname = usePathname();
  const params = useSearchParams();
  const { isPending, push } = useNavigationTransition();

  return (
    <span
      className={cn(
        'inline-block rounded-md transition-shadow duration-150',
        isPending && 'ring-2 ring-primary/70',
      )}
    >
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
