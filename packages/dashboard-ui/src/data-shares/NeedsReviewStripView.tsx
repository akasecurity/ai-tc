'use client';
import type { ReviewDestination } from '@akasecurity/schema';

import { AlertIcon, ChevronRightIcon } from '../shared/icons.tsx';

/**
 * Always-visible summary strip. The full list lives in a sheet the app opens
 * on click (see NeedsReviewListView) — the strip itself never grows, so the
 * table below it keeps a stable, full-height layout.
 */
export interface NeedsReviewStripViewProps {
  items: ReviewDestination[];
  onOpen: () => void;
}

export function NeedsReviewStripView({ items, onOpen }: NeedsReviewStripViewProps) {
  if (items.length === 0) return null;
  return (
    <div className="mb-3.5 overflow-hidden rounded-xl border border-sev-critical-fill bg-sev-critical-fill">
      <button
        type="button"
        onClick={onOpen}
        className="flex w-full cursor-pointer items-center gap-2.5 px-3.5 py-3 text-left"
      >
        <span className="grid size-6.5 shrink-0 place-items-center rounded-md bg-sev-critical-ink text-on-accent">
          <AlertIcon aria-hidden focusable={false} className="size-4" />
        </span>
        <span className="text-sm font-semibold text-text">Needs review</span>
        <span className="rounded-full bg-sev-critical-ink px-2 text-xs py-0.5 font-bold text-on-accent">
          {items.length}
        </span>
        <span className="text-xs text-text-2">
          Raw IPs, plaintext transfers &amp; unverified domains
        </span>
        <ChevronRightIcon aria-hidden focusable={false} className="ml-auto size-4.5 text-text-3" />
      </button>
    </div>
  );
}
