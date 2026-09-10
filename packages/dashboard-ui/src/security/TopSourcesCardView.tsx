import type { TopSource } from '@akasecurity/schema';
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

import { BranchIcon, TargetIcon, UserIcon } from '../shared/icons.tsx';
import { numberFormat, WidgetError } from './widget-shared.tsx';

export interface TopSourcesView {
  items: TopSource[];
  isLoading: boolean;
  error: string | null;
  /**
   * Per-source deep link, keyed by `TopSource.id`. Host-supplied so this package
   * stays router-agnostic; a source with no entry renders as plain text.
   *
   * A `user` source is expected to have none: the findings page has no author
   * dimension, only a free-text search, so a link from one could not honour the
   * count the row shows.
   */
  sourceHrefs?: Readonly<Record<string, string>> | undefined;
}

export function TopSourcesCardView({ items, isLoading, error, sourceHrefs }: TopSourcesView) {
  return (
    <Card className="flex flex-col shadow-sm min-w-0">
      <CardHeader>
        <CardIcon>
          <TargetIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Top sources</CardTitle>
          <CardDescription>Repos & people by findings</CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="flex flex-col gap-3">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          [0, 1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-7 w-full" />)
        ) : items.length === 0 ? (
          <div className="py-6 text-center text-xs text-text-3">No sources yet.</div>
        ) : (
          items.map((s) => {
            const href = sourceHrefs?.[s.id];
            return <SourceRow key={s.id} source={s} {...(href ? { href } : {})} />;
          })
        )}
      </CardContent>
    </Card>
  );
}

function SourceRow({ source, href }: { source: TopSource; href?: string }) {
  const isUser = source.kind === 'user';
  const Icon = isUser ? UserIcon : BranchIcon;
  const Row = href ? 'a' : 'div';
  return (
    <Row
      {...(href ? { href, title: `View findings from ${source.name}` } : {})}
      className={cn(
        'flex items-center gap-3',
        href &&
          '-mx-1 rounded-sm px-1 transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary/40',
      )}
    >
      <span
        className={cn(
          'flex size-7 shrink-0 items-center justify-center bg-surface-2 text-text-2',
          isUser ? 'rounded-full' : 'rounded-md',
        )}
      >
        <Icon aria-hidden focusable={false} className="size-3.5" />
      </span>
      <div className="min-w-0 flex-1 flex items-center justify-between gap-2">
        {/* `name` is a repo slug (mono reads well) or a user's email (mono looks
            off and truncates awkwardly) — only monospace the repo slug. */}
        <span
          className={cn('truncate text-sm text-text', !isUser && 'font-mono')}
          title={source.name}
        >
          {source.name}
        </span>
        <span className="text-sm font-bold text-text shrink-0">
          {numberFormat.format(source.findingsCount)}
        </span>
      </div>
    </Row>
  );
}
