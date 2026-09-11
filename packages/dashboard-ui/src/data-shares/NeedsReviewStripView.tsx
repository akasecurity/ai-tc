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
  /**
   * What the count covers, when that is wider than what the app renders under
   * the strip — e.g. "All destinations". The queue is its own unfiltered read,
   * so an app that narrows the table beneath it (by search, by kind, or both)
   * shows two numbers that disagree by design; a bare "12" over two visible
   * rows then reads as a contradiction rather than as a wider number.
   *
   * Omit it where nothing below the strip narrows the same set — including an
   * app that responds to its own filter by hiding the strip rather than
   * leaving a count above filtered rows, which needs no qualifier because the
   * two numbers are never on screen together.
   */
  scope?: string;
  onOpen: () => void;
}

export function NeedsReviewStripView({ items, scope, onOpen }: NeedsReviewStripViewProps) {
  if (items.length === 0) return null;
  return (
    <div className="mb-3.5 overflow-hidden rounded-xl border border-sev-critical-fill bg-sev-critical-fill">
      <button
        type="button"
        onClick={onOpen}
        // Opens a modal sheet, which traps focus — a screen reader announces
        // that only if the trigger says so.
        aria-haspopup="dialog"
        className="flex w-full cursor-pointer items-center gap-2.5 px-3.5 py-3 text-left"
      >
        <span className="grid size-6.5 shrink-0 place-items-center rounded-md bg-sev-critical-ink text-on-accent">
          <AlertIcon aria-hidden focusable={false} className="size-4" />
        </span>
        <span className="text-sm font-semibold text-text">Needs review</span>
        <span className="rounded-full bg-sev-critical-ink px-2 text-xs py-0.5 font-bold text-on-accent">
          {items.length}
        </span>
        {/* Sits against the count, not the description, because it qualifies
            the number. `shrink-0` + `whitespace-nowrap` keep a two-word
            qualifier off a second line when the row gets tight. */}
        {scope && (
          <span className="shrink-0 whitespace-nowrap text-xs font-semibold text-text-2">
            {scope}
          </span>
        )}
        <span className="text-xs text-text-2">
          Raw IPs, plaintext transfers &amp; unverified domains
        </span>
        <ChevronRightIcon aria-hidden focusable={false} className="ml-auto size-4.5 text-text-3" />
      </button>
    </div>
  );
}
