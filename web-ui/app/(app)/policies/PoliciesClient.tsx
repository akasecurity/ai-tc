'use client';

import { PolicyDetailView, PolicyListView } from '@akasecurity/dashboard-ui';
import type { PolicyDetail, PolicyListItem } from '@akasecurity/schema';
import { Card, cn } from '@akasecurity/ui-kit';
import { usePathname } from 'next/navigation';

import { useNavigationTransition } from '../../components/NavigationTransition';

/**
 * Client shell for the OSS Policies page. The catalog list + selected detail come
 * from the Server Component (which reads the local store per URL); selecting a
 * policy pushes a new ?id so the server re-queries the detail — the OSS store is
 * server-only, so selection can't resolve in the browser. The built-in catalog is
 * read-only (behavior is fixed), so there are no write actions here.
 */
export function PoliciesClient({
  items,
  detail,
  selectedId,
}: {
  items: PolicyListItem[];
  detail: PolicyDetail | null;
  selectedId: string;
}) {
  const pathname = usePathname();
  const { isPending, push } = useNavigationTransition();

  return (
    <div
      aria-busy={isPending}
      className={cn(
        'grid min-h-128 flex-1 grid-cols-1 gap-4 transition-shadow duration-150 lg:min-h-0 lg:grid-cols-[320px_1fr] lg:grid-rows-1',
        isPending && 'rounded-lg ring-2 ring-primary/70 ring-inset',
      )}
    >
      <PolicyListView
        items={items}
        activeId={selectedId}
        onSelect={(id) => {
          push(`${pathname}?id=${encodeURIComponent(id)}`);
        }}
      />

      {/* flex-col so the empty state below can center itself: capped to the
          viewport at `lg`, a non-flex Card leaves its `flex-1` inert and pins
          the fallback to the top of an otherwise empty pane. */}
      <Card className="flex flex-col overflow-y-auto shadow-sm">
        {/* The built-in catalog is always the 4 static archetypes and the server
            defaults the selection to the first, so `detail` is present in
            practice; this single generic fallback only covers the type's null. */}
        {detail ? (
          <PolicyDetailView policy={detail} />
        ) : (
          <div className="grid flex-1 place-items-center p-6 text-center text-sm text-text-3">
            Select a policy to view its detail.
          </div>
        )}
      </Card>
    </div>
  );
}
