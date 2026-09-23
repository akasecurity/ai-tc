'use client';

import { RecommendedActionsCardView } from '@akasecurity/dashboard-ui';
import type { DismissRecommendation, RecommendedAction } from '@akasecurity/schema';
import { useState, useTransition } from 'react';

import { dismissRecommendation } from './actions';

// Items are computed server-side (buildRecommendedActions over the findings
// that are still open — the same prioritization as the CLI TUI's Recommend
// screen). It's a Client Component because the view is interactive: the primary
// control navigates, and dismiss opens a confirmation and then writes.
//
// Dismiss used to be per-session presentation state — a Set of ids filtered out
// of the list, which came back on the next reload and told the store nothing.
// It now writes a `dismissed` disposition per finding key, which is what the
// card's own read already excludes, so the row disappears because the findings
// behind it are closed rather than because this component is hiding them.
const noop = (): void => undefined;

export function RecommendedActionsCard({
  items,
  viewAllHref,
}: {
  items: RecommendedAction[];
  viewAllHref: string;
}) {
  const [isMutating, startTransition] = useTransition();
  const [mutationError, setMutationError] = useState<string | null>(null);

  // Resolves what the dialog needs to decide whether to close: `true` only when
  // the write landed. `isMutating` cannot answer that — it falls back to false
  // on a refusal exactly as on a success.
  const dismissAction = (request: DismissRecommendation): Promise<boolean> =>
    new Promise<boolean>((resolve) => {
      startTransition(async () => {
        try {
          const result = await dismissRecommendation(request);
          setMutationError(result.ok ? null : (result.error ?? 'The dismissal was refused.'));
          // The action revalidates /security, so a successful write re-renders
          // this card from the store with the rule's row gone. Nothing is
          // filtered client-side, so the list on screen is always the store's.
          resolve(result.ok);
        } catch {
          // A Server Action REJECTS rather than returns when the request never
          // completes — the POST fails, or Next raises before the action's own
          // code runs. Unguarded, the `await` throws, `resolve` is never
          // reached, and this promise stays pending for ever: the dialog waits
          // on a `.then` that cannot fire, shows no message because nothing set
          // one, and leaves an unhandled rejection behind. Settling as a
          // refusal is what puts the reader back in a state they can act from.
          //
          // Deliberately does NOT claim the dismissal did not happen. A request
          // that failed after the server committed is indistinguishable from
          // one that never arrived, so the wording sends the reader to the
          // findings list rather than asserting either.
          setMutationError(
            'The dismissal could not be completed — check the Findings page to see whether it was recorded, then try again.',
          );
          resolve(false);
        }
      });
    });

  return (
    <RecommendedActionsCardView
      items={items}
      isLoading={false}
      error={null}
      viewAllHref={viewAllHref}
      applyAction={noop}
      dismissAction={dismissAction}
      isMutating={isMutating}
      mutationError={mutationError}
    />
  );
}
