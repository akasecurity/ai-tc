'use client';
import type { BlockedDetectionDescriptor } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { BLOCKED_WINDOW_PHRASE, type BlockedWindow } from '../lib/timeRanges.ts';
import { SlashCircleIcon } from '../shared/icons.tsx';
import { BlockedWindowSelect } from './BlockedWindowSelect.tsx';

export interface BlockedLedgerViewProps {
  items: BlockedDetectionDescriptor[];
  onApprove: (reference: string) => void;
  blockedWindow: BlockedWindow;
  onBlockedWindowChange: (window: BlockedWindow) => void;
  /**
   * Why this row cannot be approved, or null when it can — asked PER ROW, and
   * answered by the host rather than derived here.
   *
   * Approvability is a property of the machine that recorded the block: a row
   * can only be matched under the fingerprint key it was written with, and that
   * key lives on that machine. A host serving ONE machine answers from its own
   * key state, and `blockedRowBlockReason` is exactly that answer — pass
   * `(row) => blockedRowBlockReason(row, keyState)`.
   *
   * It is a callback rather than a `FingerprintKeyState` prop because a host
   * that aggregates SEVERAL machines has no single key state to give: rows in
   * one list were recorded under different keys on different machines, so one
   * value would be wrong for most of them, and the remediation copy that
   * follows from it ("check the permissions on ~/.aka/data") names a file such
   * a host does not have. Returning the reason per row lets each host say
   * something true, and keeps this view from assuming it is running beside the
   * store it is describing.
   *
   * The string is shown to the reader and used as the disabled Approve's title,
   * so it should say what happened and what to do about it.
   */
  blockReason: (row: BlockedDetectionDescriptor) => string | null;
}

/**
 * The "blocked in the last N" strip — the web twin of the
 * `aka exception approve` picker, with a lookback window filter the CLI
 * doesn't have. Each row carries the masked preview only (never the raw value
 * or its keyed fingerprint); Approve opens the grant dialog for that entry,
 * and the server re-reads the full ledger row by `reference`.
 *
 * The ledger is retained for a day, so it outlives a key rotation and keeps
 * listing rows fingerprinted under the old key. Those rows are shown — they are
 * still an accurate record of what was blocked — but marked unapprovable, since
 * a grant built from one could never match at enforcement time. WHICH rows
 * those are is the host's to say (see `blockReason`): this view renders the
 * answer, it does not work it out.
 */
export function BlockedLedgerView({
  items,
  onApprove,
  blockedWindow,
  onBlockedWindowChange,
  blockReason,
}: BlockedLedgerViewProps) {
  return (
    <div className="mb-3.5 overflow-hidden rounded-xl border border-sev-high-fill bg-sev-high-fill">
      <div className="flex items-center gap-2.5 px-3.5 py-3">
        <span className="grid size-6.5 shrink-0 place-items-center rounded-md bg-sev-high-ink text-on-accent">
          <SlashCircleIcon aria-hidden focusable={false} className="size-4" />
        </span>
        <span className="text-sm font-semibold text-text">Recently blocked</span>
        <span className="rounded-full bg-sev-high-ink px-2 py-0.5 text-xs font-bold text-on-accent">
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
            const blocked = blockReason(b);
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
                    {blocked === null ? '' : ' · not approvable'}
                  </div>
                  {blocked === null ? null : (
                    <div className="mt-1 text-label text-text-3">{blocked}</div>
                  )}
                </div>
                <Button
                  onClick={() => {
                    onApprove(b.reference);
                  }}
                  disabled={blocked !== null}
                  title={blocked ?? undefined}
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
