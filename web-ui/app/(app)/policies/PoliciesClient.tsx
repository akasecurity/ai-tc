'use client';

import { PolicyDetailView, PolicyListView } from '@akasecurity/dashboard-ui';
import type { PolicyDetail, PolicyListItem } from '@akasecurity/schema';
import { Card } from '@akasecurity/ui-kit';
import { usePathname, useRouter } from 'next/navigation';

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
  const router = useRouter();
  const pathname = usePathname();

  return (
    <div className="grid min-h-128 flex-1 grid-cols-1 gap-4 lg:grid-cols-[320px_1fr] lg:grid-rows-1">
      <PolicyListView
        items={items}
        activeId={selectedId}
        onSelect={(id) => {
          router.push(`${pathname}?id=${encodeURIComponent(id)}`);
        }}
      />

      <Card className="overflow-y-auto shadow-sm">
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
