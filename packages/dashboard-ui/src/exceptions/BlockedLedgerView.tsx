'use client';
import type { BlockedDetection } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { BLOCKED_WINDOW_PHRASE, type BlockedWindow } from '../lib/timeRanges.ts';
import { SlashCircleIcon } from '../shared/icons.tsx';
import { BlockedWindowSelect } from './BlockedWindowSelect.tsx';
import { isBlockedRowApprovable } from './meta.ts';

export interface BlockedLedgerViewProps {
  items: BlockedDetection[];
  onApprove: (reference: string) => void;
  blockedWindow: BlockedWindow;
  onBlockedWindowChange: (window: BlockedWindow) => void;
  /**
   * The fingerprint key version in use now, or null when there is no key file.
   * A row recorded under any other version can no longer be matched, so its
   * Approve is disabled rather than left to fail server-side.
   */
  keyVersion: number | null;
}

/**
 * The "blocked in the last N" strip — the web twin of the
 * `aka exception approve` picker, with a lookback window filter the CLI
 * doesn't have. Each row carries the keyed fingerprint and masked preview
 * only (never the raw value); Approve opens the grant dialog for that entry.
 *
 * The ledger is retained for a day, so it outlives a key rotation and keeps
 * listing rows fingerprinted under the old key. Those rows are shown — they are
 * still an accurate record of what was blocked — but marked unapprovable, since
 * a grant built from one could never match at enforcement time.
 */
export function BlockedLedgerView({
  items,
  onApprove,
  blockedWindow,
  onBlockedWindowChange,
  keyVersion,
}: BlockedLedgerViewProps) {
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
          Detections blocked in {BLOCKED_WINDOW_PHRASE[blockedWindow]} — approve one to grant an
          exception
        </span>
        <span className="ml-auto shrink-0">
          <BlockedWindowSelect value={blockedWindow} onChange={onBlockedWindowChange} />
        </span>
      </div>
      {items.length === 0 ? (
        <div className="px-3.5 pb-3.5 text-xs text-text-2">Nothing blocked in this window.</div>
      ) : (
        <div className="flex flex-col gap-1.5 px-3 pb-3">
          {items.map((b) => {
            const stale = !isBlockedRowApprovable(b, keyVersion);
            return (
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
                    {stale
                      ? ` · recorded under fingerprint key v${String(b.keyVersion)} — no longer approvable`
                      : ''}
                  </div>
                </div>
                <Button
                  onClick={() => {
                    onApprove(b.reference);
                  }}
                  disabled={stale}
                  title={
                    stale
                      ? 'The fingerprint key changed after this was blocked, so a grant from it could never match. Trigger the detection again.'
                      : undefined
                  }
                  variant="ghost"
                  tone="primary"
                  size="sm"
                >
                  Approve
                </Button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
