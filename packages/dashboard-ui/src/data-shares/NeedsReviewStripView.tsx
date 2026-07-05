'use client';
import type { ReviewDestination } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';

import { AlertIcon, ChevronDownIcon } from '../shared/icons.tsx';
import { ClassTag, DestMark } from './atoms.tsx';
import { flagReason } from './meta.ts';

export interface NeedsReviewStripViewProps {
  items: ReviewDestination[];
  open: boolean;
  onToggle: () => void;
  onReview: (id: string) => void;
}

export function NeedsReviewStripView({
  items,
  open,
  onToggle,
  onReview,
}: NeedsReviewStripViewProps) {
  if (items.length === 0) return null;
  return (
    <div className="mb-3.5 overflow-hidden rounded-xl border border-sev-critical-fill bg-sev-critical-fill">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center gap-2.5 px-3.5 py-3 text-left"
      >
        <span className="grid size-6.5 shrink-0 place-items-center rounded-md bg-sev-critical text-white">
          <AlertIcon aria-hidden focusable={false} className="size-4" />
        </span>
        <span className="text-sm font-semibold text-text">Needs review</span>
        <span className="rounded-full bg-sev-critical px-2 text-xs py-0.5 font-bold text-white">
          {items.length}
        </span>
        <span className="text-xs text-text-2">
          Raw IPs, plaintext transfers &amp; unverified domains
        </span>
        <ChevronDownIcon
          aria-hidden
          focusable={false}
          className={cn('ml-auto size-4.5 text-text-3 transition-transform', !open && '-rotate-90')}
        />
      </button>
      {open && (
        <div className="flex flex-col gap-1.5 px-3 pb-3">
          {items.map((d) => (
            <div
              key={d.id}
              className="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5"
            >
              <DestMark kind={d.kind} trust={d.trust} name={d.name} size={30} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      'text-xs font-semibold text-text',
                      d.kind === 'ip' && 'font-mono',
                    )}
                  >
                    {d.name}
                  </span>
                  <ClassTag cls={d.topDataClass} />
                </div>
                <div className="mt-1.5 flex items-center gap-1.5 text-label text-sev-critical">
                  <AlertIcon aria-hidden focusable={false} className="size-3" />
                  {flagReason(d.review.reasons)}
                </div>
              </div>
              <span className="text-xs text-text-3">
                {d.callSiteCount} call{d.callSiteCount === 1 ? '' : 's'}
              </span>
              <Button
                onClick={() => {
                  onReview(d.id);
                }}
                variant="ghost"
                tone="primary"
                size="sm"
              >
                Review
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
