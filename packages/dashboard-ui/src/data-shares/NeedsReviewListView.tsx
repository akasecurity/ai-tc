'use client';
import type { ReviewDestination } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';

import { AlertIcon, CheckCircleIcon } from '../shared/icons.tsx';
import { ClassTag, DestMark } from './atoms.tsx';
import { bindId } from './bindings.ts';
import { flagReason } from './meta.ts';

/**
 * Body of the needs-review sheet the app opens from NeedsReviewStripView.
 * Same per-destination row markup the strip used to render inline.
 */
export interface NeedsReviewListViewProps {
  items: ReviewDestination[];
  onReview: (id: string) => void;
}

export function NeedsReviewListView({ items, onReview }: NeedsReviewListViewProps) {
  // The sheet outlives its own list: it stays open while the user works
  // through the flagged destinations, and the last one can clear while it is
  // still showing. Say so rather than rendering an empty box.
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center text-text-3">
        <CheckCircleIcon aria-hidden focusable={false} className="size-6 text-ok-ink" />
        <div className="text-sm">Nothing needs review</div>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {items.map((d) => (
        <div
          key={d.id}
          className="flex items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2.5"
        >
          <DestMark kind={d.kind} trust={d.trust} name={d.name} host={d.host} size={30} />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span
                className={cn('text-xs font-semibold text-text', d.kind === 'ip' && 'font-mono')}
              >
                {d.name}
              </span>
              <ClassTag cls={d.topDataClass} />
            </div>
            <div className="mt-1.5 flex items-center gap-1.5 text-label text-sev-critical-ink">
              <AlertIcon aria-hidden focusable={false} className="size-3" />
              {flagReason(d.review.reasons)}
            </div>
          </div>
          <span className="text-xs text-text-3">
            {d.callSiteCount} call{d.callSiteCount === 1 ? '' : 's'}
          </span>
          <Button onClick={bindId(onReview, d.id)} variant="ghost" tone="primary" size="sm">
            Review
          </Button>
        </div>
      ))}
    </div>
  );
}
