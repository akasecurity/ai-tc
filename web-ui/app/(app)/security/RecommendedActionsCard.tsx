'use client';

import { RecommendedActionsCardView } from '@akasecurity/dashboard-ui';
import type { RecommendedAction } from '@akasecurity/schema';
import { useState } from 'react';

// Items are computed server-side (buildRecommendedActions over recent
// findings — the same prioritization as the CLI TUI's Recommend screen). It's
// a Client Component because the view is interactive: every action navigates
// (the view renders an <a href>), and dismiss is per-session presentation
// state — the local store has no server-side apply/dismiss.
const noop = (): void => undefined;

export function RecommendedActionsCard({ items }: { items: RecommendedAction[] }) {
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(new Set());

  return (
    <RecommendedActionsCardView
      items={items.filter((a) => !dismissed.has(a.id))}
      isLoading={false}
      error={null}
      applyAction={noop}
      dismissAction={(id) => {
        setDismissed((prev) => new Set([...prev, id]));
      }}
      isMutating={false}
      mutationError={null}
    />
  );
}
