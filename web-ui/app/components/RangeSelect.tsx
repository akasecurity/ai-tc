'use client';

import { type TimeRange, TimeRangeSelect } from '@akasecurity/dashboard-ui';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

// Client wrapper that drives the security range off the URL: picking a range
// pushes ?range=… so the Server Component re-fetches db.security.* for it.
export function RangeSelect({ value }: { value: TimeRange }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();

  return (
    <TimeRangeSelect
      value={value}
      onChange={(next) => {
        const sp = new URLSearchParams(params.toString());
        sp.set('range', next);
        router.push(`${pathname}?${sp.toString()}`);
      }}
    />
  );
}
