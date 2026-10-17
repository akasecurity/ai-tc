'use client';

// Right pane for a harness (Claude Code / Cursor / Codex …): every project and
// asset it loads, as one table, with its recent block/redact/warn events above.
import type { HarnessEventKind, HarnessEventsResponse, HarnessSummary } from '@akasecurity/schema';
import { Badge, cn } from '@akasecurity/ui-kit';
import { useMemo } from 'react';

import { dayLabel } from '../activity/format.ts';
import { formatDateTime } from '../lib/dateFormat.ts';
import { Provider } from '../shared/Provider.tsx';
import { EVENT_KIND, harnessRows, type InventoryRow, needsAttention } from './data.ts';
import { Ico } from './Ico.tsx';
import { InventoryTable } from './InventoryTable.tsx';

const EVENT_KINDS: HarnessEventKind[] = ['block', 'redact', 'warn'];

const EVENT_TIME: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' };

/** "Today · 09:19" for an event, bucketed against `now` and formatted in `locale`. */
function formatEvent(iso: string, now: number, locale: string): { day: string; time: string } {
  const time = formatDateTime(Date.parse(iso), locale, EVENT_TIME);
  return { day: dayLabel(iso, new Date(now)), time };
}

const plural = (n: number, one: string, many: string): string =>
  `${String(n)} ${n === 1 ? one : many}`;

export function HarnessInventory({
  harness,
  events,
  onOpen,
  renderedAt,
  locale,
}: {
  harness: HarnessSummary;
  events: HarnessEventsResponse | null;
  onOpen: (row: InventoryRow) => void;
  /** The instant this render is measured against, in epoch milliseconds. */
  renderedAt: number;
  /** The locale event times are formatted in. */
  locale: string;
}) {
  const rows = useMemo(() => harnessRows(harness), [harness]);
  const attention = rows.filter(needsAttention).length;
  const subtitle = [
    harness.version,
    plural(harness.sessions, 'session', 'sessions'),
    plural(rows.length, 'asset', 'assets'),
    `${attention > 0 ? String(attention) : 'none'} need attention`,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <InventoryTable
      title={harness.label}
      subtitle={subtitle}
      avatar={<Provider id={harness.id} size={40} />}
      rows={rows}
      type={null}
      searchNoun="inventory"
      onOpen={onOpen}
      renderedAt={renderedAt}
    >
      <HarnessEvents events={events} renderedAt={renderedAt} locale={locale} />
    </InventoryTable>
  );
}

function HarnessEvents({
  events,
  renderedAt,
  locale,
}: {
  events: HarnessEventsResponse | null;
  renderedAt: number;
  locale: string;
}) {
  const items = events?.items ?? [];
  const counts = events?.counts;
  const total = counts ? counts.block + counts.redact + counts.warn : 0;

  if (items.length === 0) {
    return (
      <div className="flex items-center gap-2 border-b border-border px-5 py-2.5 text-xs text-text-3">
        <Ico name="check-circle" className="size-3.5 text-ok-ink" />
        No blocks, redactions or warnings from this harness
      </div>
    );
  }

  return (
    <details className="group border-b border-border px-5 py-2.5">
      <summary className="flex cursor-pointer list-none items-center gap-2 [&::-webkit-details-marker]:hidden">
        <Ico
          name="chevron-right"
          className="size-3.5 text-text-3 transition-transform group-open:rotate-90"
        />
        <span className="text-label font-semibold uppercase tracking-wider text-text-3">
          Recent blocks, redactions &amp; warnings
        </span>
        {counts && (
          <span className="ml-auto inline-flex items-center gap-1.5">
            {EVENT_KINDS.map((k) =>
              counts[k] > 0 ? (
                <Badge key={k} variant={EVENT_KIND[k].tone}>
                  {counts[k]} {EVENT_KIND[k].label.toLowerCase()}
                </Badge>
              ) : null,
            )}
          </span>
        )}
      </summary>
      <div className="mt-2.5 flex max-h-64 flex-col gap-1.5 overflow-y-auto">
        {items.map((x) => {
          const m = EVENT_KIND[x.kind];
          const { day, time } = formatEvent(x.occurredAt, renderedAt, locale);
          return (
            <div
              key={`${x.occurredAt}·${x.title}`}
              className="flex items-start gap-2.5 rounded-lg border border-border bg-surface px-3 py-2"
            >
              <span
                className={cn('grid size-6.5 shrink-0 place-items-center rounded-md', m.bg, m.fg)}
              >
                <Ico name={m.icon} className="size-3.5" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-text">{x.title}</div>
                <div className="mt-0.5 truncate font-mono text-xs text-text-3">{x.detail}</div>
              </div>
              <div className="flex shrink-0 flex-col items-end gap-1">
                <Badge variant={m.tone}>{m.label}</Badge>
                <span className="font-mono text-xs text-text-3">
                  {day} · {time}
                </span>
              </div>
            </div>
          );
        })}
        {total > items.length && (
          <div className="text-center text-xs text-text-3">
            Showing {items.length} of {total} events
          </div>
        )}
      </div>
    </details>
  );
}
