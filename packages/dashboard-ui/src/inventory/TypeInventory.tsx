'use client';

// Right pane for one asset type: every project, skill, MCP server, hook or
// config file in the inventory, with that type's own columns and status pills.
import type { AssetType } from '@akasecurity/schema';
import { cn } from '@akasecurity/ui-kit';

import { inlineLabel, type InventoryRow, needsAttention, typeMeta } from './data.ts';
import { Ico } from './Ico.tsx';
import { InventoryTable } from './InventoryTable.tsx';

export function TypeInventory({
  type,
  rows,
  onOpen,
  renderedAt,
}: {
  type: AssetType;
  rows: InventoryRow[];
  onOpen: (row: InventoryRow) => void;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
}) {
  const meta = typeMeta(type);
  const attention = rows.filter(needsAttention).length;
  return (
    <InventoryTable
      title={meta.label}
      subtitle={`${String(rows.length)} ${rows.length === 1 ? 'asset' : 'assets'} · ${
        attention > 0 ? String(attention) : 'none'
      } need attention`}
      avatar={
        <span
          className={cn('grid size-10 shrink-0 place-items-center rounded-lg', meta.bg, meta.fg)}
        >
          <Ico name={meta.icon} className="size-5" />
        </span>
      }
      rows={rows}
      type={type}
      searchNoun={inlineLabel(meta.label)}
      onOpen={onOpen}
      renderedAt={renderedAt}
    />
  );
}
