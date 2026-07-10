import type { ResolvedFeedItem } from '@akasecurity/schema';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  cn,
  Skeleton,
} from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { CheckCircleIcon } from '../shared/icons.tsx';
import { SEVERITY_META, SEVERITY_TILE } from './meta.ts';
import { WidgetEmpty, WidgetError } from './widget-shared.tsx';

export interface RecentlyResolvedView {
  items: ResolvedFeedItem[];
  isLoading: boolean;
  error: string | null;
}

/** The recently-resolved feed: a vertical timeline of findings moved to resolved,
 * newest first. */
export function RecentlyResolvedCardView({ items, isLoading, error }: RecentlyResolvedView) {
  return (
    <Card className="flex h-full flex-col shadow-sm">
      <CardHeader>
        <CardIcon>
          <CheckCircleIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Recently resolved</CardTitle>
          <CardDescription>Findings moved to resolved, newest first</CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="flex flex-col">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <div className="flex flex-col gap-3 py-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <WidgetEmpty message="No resolved findings yet." />
        ) : (
          items.map((item, i) => (
            <ResolvedRow key={item.findingKey} item={item} last={i === items.length - 1} />
          ))
        )}
      </CardContent>
    </Card>
  );
}

function ResolvedRow({ item, last }: { item: ResolvedFeedItem; last: boolean }) {
  return (
    <div className={cn('relative flex gap-3', !last && 'pb-4')}>
      {/* Connector line to the next item — centered under the 32px icon tile. */}
      {!last && <span className="absolute bottom-0 left-4 top-8 w-px bg-text/6" />}
      <span
        className={cn(
          'z-10 grid size-8 shrink-0 place-items-center rounded-lg',
          SEVERITY_TILE[item.severity],
        )}
      >
        <CheckCircleIcon aria-hidden focusable={false} className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-semibold text-text">{item.ruleId}</span>
          <span className="ml-auto shrink-0 text-xs text-text-3">
            {relativeTime(item.resolvedAt)}
          </span>
        </div>
        <div className="mt-1.5 flex items-center gap-1.5 text-xs text-text-3">
          <span className="shrink-0">{SEVERITY_META[item.severity].label}</span>
          <span className="shrink-0 text-border-strong">·</span>
          <span className="truncate font-mono">{item.path}</span>
        </div>
      </div>
    </div>
  );
}
