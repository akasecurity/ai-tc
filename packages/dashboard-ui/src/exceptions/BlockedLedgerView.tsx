'use client';
import type { BlockedDetection } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { SlashCircleIcon } from '../shared/icons.tsx';

export interface BlockedLedgerViewProps {
  items: BlockedDetection[];
  onApprove: (reference: string) => void;
}

/**
 * The "blocked in the last 30 minutes" strip — the web twin of the
 * `aka exception approve` picker. Each row carries the keyed fingerprint and
 * masked preview only (never the raw value); Approve opens the grant dialog
 * for that entry.
 */
export function BlockedLedgerView({ items, onApprove }: BlockedLedgerViewProps) {
  if (items.length === 0) return null;
  return (
    <div className="mb-3.5 overflow-hidden rounded-xl border border-sev-high-fill bg-sev-high-fill">
      <div className="flex items-center gap-2.5 px-3.5 py-3">
        <span className="grid size-6.5 shrink-0 place-items-center rounded-md bg-sev-high text-white">
          <SlashCircleIcon aria-hidden focusable={false} className="size-4" />
        </span>
        <span className="text-sm font-semibold text-text">Recently blocked</span>
        <span className="rounded-full bg-sev-high px-2 py-0.5 text-xs font-bold text-white">
          {items.length}
        </span>
        <span className="text-xs text-text-2">
          Detections blocked in the last 30 minutes — approve one to grant an exception
        </span>
      </div>
      <div className="flex flex-col gap-1.5 px-3 pb-3">
        {items.map((b) => (
          <div
            key={b.reference}
            className="flex items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2.5"
          >
            <span className="font-mono text-xs font-semibold text-text-3">{b.reference}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-text">{b.ruleId}</span>
                <span className="font-mono text-xs text-text-2">{b.maskedValue}</span>
              </div>
              <div className={cn('mt-1 text-label text-text-3')}>
                {relativeTime(b.blockedAt)}
                {b.repo ? ` · ${b.repo}` : ''}
              </div>
            </div>
            <Button
              onClick={() => {
                onApprove(b.reference);
              }}
              variant="ghost"
              tone="primary"
              size="sm"
            >
              Approve
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}
