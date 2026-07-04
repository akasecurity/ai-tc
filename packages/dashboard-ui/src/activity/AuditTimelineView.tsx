// The audit-log timeline: a vertical rail of events, each with a tinted node,
// timestamp, title + badges, and detail line. Presentational — takes events via props.
import { Badge, Button, cn, SeverityBadge } from '@akasecurity/ui-kit';

import { AlertIcon, ArrowUpRightIcon, ShieldCheckIcon } from '../shared/icons.tsx';
import { EVENT_META, LINK_LABEL, TOOL_META } from './meta.ts';
import type { AuditEvent } from './types.ts';

function EventRow({ event, first, last }: { event: AuditEvent; first: boolean; last: boolean }) {
  const meta = EVENT_META[event.kind];
  const Icon =
    event.kind === 'tool' && event.tool ? (TOOL_META[event.tool] ?? meta.icon) : meta.icon;
  const pulse = event.kind === 'active';
  const mono = event.kind === 'tool' || event.kind === 'commit';
  const linkLabel = event.link ? LINK_LABEL[event.link] : null;

  return (
    <div className="grid grid-cols-[60px_24px_1fr] gap-x-3">
      <div className="whitespace-nowrap pt-1.5 text-right font-mono text-label text-text-3">
        {event.time}
      </div>
      <div className="relative flex justify-center">
        {!(first && last) && (
          <span
            className={cn(
              'absolute left-1/2 w-px -translate-x-1/2 bg-border',
              first ? 'bottom-0 top-3' : last ? 'top-0 h-3' : 'inset-y-0',
            )}
          />
        )}
        <span
          className={cn(
            'relative z-10 grid size-6 place-items-center rounded-md ring-2 ring-surface',
            meta.fill,
            meta.text,
          )}
        >
          {pulse && (
            <span className="absolute inset-0 animate-ping rounded-md bg-current opacity-30" />
          )}
          <Icon aria-hidden focusable={false} className="relative size-3.5" />
        </span>
      </div>
      <div className={cn('pt-0.5', last ? 'pb-0' : 'pb-4.5')}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-ui font-semibold text-text">{event.title}</span>
          {event.sev && <SeverityBadge severity={event.sev} />}
          {event.flagged && (
            <Badge variant="critical" className="h-6 gap-1.5">
              <AlertIcon aria-hidden focusable={false} className="size-3" />
              Flagged
            </Badge>
          )}
          {event.internal && (
            <Badge variant="primary" className="h-6 gap-1.5">
              <ShieldCheckIcon aria-hidden focusable={false} className="size-3" />
              Internal
            </Badge>
          )}
        </div>
        <div className={cn('mt-0.5 text-xs text-text-2', mono && 'font-mono')}>
          {event.detail}
          {linkLabel && (
            <Button variant="link" tone="primary" className="ml-2 text-xs font-normal">
              Open in {linkLabel}
              <ArrowUpRightIcon aria-hidden focusable={false} />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export function AuditTimelineView({ events }: { events: AuditEvent[] }) {
  return (
    <div>
      {events.map((event, i) => (
        <EventRow
          key={`${event.time}-${String(i)}`}
          event={event}
          first={i === 0}
          last={i === events.length - 1}
        />
      ))}
    </div>
  );
}
