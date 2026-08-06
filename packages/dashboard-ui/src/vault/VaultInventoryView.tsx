'use client';
import type { VaultInventoryEntry } from '@akasecurity/schema';
import {
  Button,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { ScrubbedValue } from '../shared/ScrubbedValue.tsx';
import { RevealToModelBadge, SightingKindChip } from './atoms.tsx';

export interface VaultInventoryViewProps {
  entries: VaultInventoryEntry[];
  // Owner-surface reveal by row id; omitting it renders the table read-only.
  onReveal?: (pointerId: string) => void;
  // Revoke the active reveal-to-model grant covering the row's value.
  onRevoke?: (grantId: string) => void;
  // Whether the store holds a page after / before the one passed in.
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  /**
   * Step the window. Absent ⇒ the caller cannot paginate, and the truncation
   * notice is shown instead — which is the honest thing to render when there is
   * more data and no way to reach it.
   */
  onNextPage?: (() => void) | undefined;
  onPreviousPage?: (() => void) | undefined;
  loadingNextPage?: boolean;
  // 1-based position of this window's first row in the whole list.
  pageStart?: number | undefined;
  // Vaulted values across the whole store, not just this page.
  total?: number | undefined;
}

const COLUMN_CLASS: Record<string, string> = {
  occurrences: 'min-w-[120px] whitespace-nowrap',
  firstSeen: 'min-w-[110px] whitespace-nowrap',
  lastSeen: 'min-w-[110px] whitespace-nowrap',
  grant: 'min-w-[140px] whitespace-nowrap',
  action: 'min-w-[120px] whitespace-nowrap',
};

/**
 * The vault register — every value currently held, raw-free: the masked
 * preview is the value's identity for humans. Each row also lists the places
 * the value's POINTER has been written (its sightings): pointers are
 * deterministic, so anyone who can read those locations sees the correlation.
 */
export function VaultInventoryView({
  entries,
  onReveal,
  onRevoke,
  hasNextPage = false,
  hasPreviousPage = false,
  onNextPage,
  onPreviousPage,
  loadingNextPage = false,
  pageStart,
  total,
}: VaultInventoryViewProps) {
  if (entries.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface py-10 text-center text-sm text-text-3">
        Nothing vaulted yet — values land here when a redact policy fires with vault consent
        granted.
      </div>
    );
  }
  const hasActions = onReveal !== undefined || onRevoke !== undefined;
  return (
    <div className="overflow-x-auto rounded-xl border border-border bg-surface p-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Value</TableHead>
            <TableHead className={COLUMN_CLASS.occurrences}>Occurrences</TableHead>
            <TableHead className={COLUMN_CLASS.firstSeen}>First seen</TableHead>
            <TableHead className={COLUMN_CLASS.lastSeen}>Last seen</TableHead>
            <TableHead className={COLUMN_CLASS.grant}>Grant</TableHead>
            {hasActions ? <TableHead className={COLUMN_CLASS.action}>Actions</TableHead> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {entries.map((entry) => (
            <VaultInventoryRow
              key={entry.pointerId}
              entry={entry}
              hasActions={hasActions}
              onReveal={onReveal}
              onRevoke={onRevoke}
            />
          ))}
        </TableBody>
      </Table>
      {onNextPage ? (
        <Pagination>
          <PaginationPrevious
            disabled={!hasPreviousPage || loadingNextPage}
            onClick={onPreviousPage}
          />
          <PaginationStatus>
            {total === undefined || pageStart === undefined
              ? `${String(entries.length)} shown`
              : `${String(pageStart)}–${String(pageStart + entries.length - 1)} of ${String(total)} values`}
          </PaginationStatus>
          <PaginationNext
            disabled={!hasNextPage || loadingNextPage}
            loading={loadingNextPage}
            onClick={onNextPage}
          />
        </Pagination>
      ) : (
        hasNextPage && (
          <p className="mt-4 text-center text-xs text-text-3">
            Showing the first {entries.length} values — the rest are in the store.
          </p>
        )
      )}
    </div>
  );
}

function VaultInventoryRow({
  entry,
  hasActions,
  onReveal,
  onRevoke,
}: {
  entry: VaultInventoryEntry;
  hasActions: boolean;
  onReveal?: ((pointerId: string) => void) | undefined;
  onRevoke?: ((grantId: string) => void) | undefined;
}) {
  const grantId = entry.revealGrantId;
  const columns = hasActions ? 6 : 5;
  return (
    <>
      <TableRow>
        <TableCell>
          <ScrubbedValue value={null} descriptor={entry} />
        </TableCell>
        <TableCell className={COLUMN_CLASS.occurrences}>
          <span className="text-xs text-text-2">{String(entry.occurrences)}</span>
        </TableCell>
        <TableCell className={COLUMN_CLASS.firstSeen}>
          <span className="text-xs text-text-2">{relativeTime(entry.firstSeen)}</span>
        </TableCell>
        <TableCell className={COLUMN_CLASS.lastSeen}>
          <span className="text-xs text-text-2">{relativeTime(entry.lastSeen)}</span>
        </TableCell>
        <TableCell className={COLUMN_CLASS.grant}>
          {grantId === null ? null : <RevealToModelBadge />}
        </TableCell>
        {hasActions ? (
          <TableCell className={COLUMN_CLASS.action}>
            <span className="inline-flex items-center gap-2">
              {onReveal === undefined ? null : (
                <Button
                  variant="outline"
                  tone="neutral"
                  size="sm"
                  onClick={() => {
                    onReveal(entry.pointerId);
                  }}
                >
                  Reveal
                </Button>
              )}
              {grantId !== null && onRevoke !== undefined ? (
                <Button
                  variant="ghost"
                  tone="danger"
                  size="sm"
                  onClick={() => {
                    onRevoke(grantId);
                  }}
                >
                  Revoke grant
                </Button>
              ) : null}
            </span>
          </TableCell>
        ) : null}
      </TableRow>
      {entry.sightings.length > 0 ? (
        <TableRow>
          <TableCell colSpan={columns} className="py-2">
            <details>
              <summary className="cursor-pointer text-xs font-medium text-text-2">
                Written to {String(entry.sightings.length)}{' '}
                {entry.sightings.length === 1 ? 'location' : 'locations'} — anyone who can read them
                sees the correlation
              </summary>
              <ul className="mt-2 flex flex-col gap-2">
                {entry.sightings.map((sighting) => (
                  <li
                    key={`${sighting.kind}:${sighting.location}`}
                    className="grid grid-cols-[1fr_110px_100px] items-center gap-2 text-xs text-text-2"
                  >
                    <code className="break-all font-mono">{sighting.location}</code>
                    <div>
                      <SightingKindChip kind={sighting.kind} />
                    </div>
                    <span className="text-text-3">{relativeTime(sighting.lastSeen)}</span>
                  </li>
                ))}
              </ul>
            </details>
          </TableCell>
        </TableRow>
      ) : null}
    </>
  );
}
