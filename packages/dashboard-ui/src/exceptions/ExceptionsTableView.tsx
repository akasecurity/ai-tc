'use client';
import type { DetectionException } from '@akasecurity/schema';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { StateTagFor } from './atoms.tsx';
import { SCOPE_LABEL, VIA_LABEL } from './meta.ts';

export interface ExceptionsTableViewProps {
  items: DetectionException[];
  // True when terminal (consumed/expired/revoked) rows are included — the
  // audit view; affects only the empty-state copy.
  includeTerminal: boolean;
  onSelect: (id: string) => void;
}

/**
 * The grants register — mirrors `aka exception list [--all]`. Fingerprints are
 * never shown here (they're derived audit detail); the masked preview is the
 * value's identity for humans.
 */
export function ExceptionsTableView({
  items,
  includeTerminal,
  onSelect,
}: ExceptionsTableViewProps) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface py-10 text-center text-sm text-text-3">
        {includeTerminal
          ? 'No exceptions have ever been granted.'
          : 'No active exceptions — enforcement applies everywhere.'}
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-xl border border-border bg-surface">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Rule</TableHead>
            <TableHead>Value</TableHead>
            <TableHead>Scope</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Uses</TableHead>
            <TableHead>Created</TableHead>
            <TableHead>State</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((ex) => (
            <TableRow
              key={ex.id}
              className="cursor-pointer"
              onClick={() => {
                onSelect(ex.id);
              }}
            >
              <TableCell className="font-mono text-xs text-text-3">{ex.id.slice(0, 8)}</TableCell>
              <TableCell className="font-mono text-xs">{ex.ruleId}</TableCell>
              <TableCell className="font-mono text-xs">{ex.maskedValue}</TableCell>
              <TableCell className="text-xs">{SCOPE_LABEL[ex.scope]}</TableCell>
              <TableCell className="text-xs text-text-2">
                {ex.expiresAt === null ? '—' : relativeTime(ex.expiresAt)}
              </TableCell>
              <TableCell className="text-xs text-text-2">
                {ex.maxUses === null
                  ? String(ex.useCount)
                  : `${String(ex.useCount)}/${String(ex.maxUses)}`}
              </TableCell>
              <TableCell className="text-xs text-text-2">
                {relativeTime(ex.createdAt)} · {VIA_LABEL[ex.createdVia]}
              </TableCell>
              <TableCell>
                <StateTagFor exception={ex} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
