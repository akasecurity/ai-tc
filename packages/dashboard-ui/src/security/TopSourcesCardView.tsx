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

import { BranchIcon, TargetIcon, UserIcon } from './icons.tsx';
import { numberFormat, WidgetError } from './widget-shared.tsx';

export interface TopSourcesView {
  items: TopSource[];
  isLoading: boolean;
  error: string | null;
}

export function TopSourcesCardView({ items, isLoading, error }: TopSourcesView) {
  return (
    <Card className="flex flex-col shadow-sm">
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
          items.map((s) => <SourceRow key={s.id} source={s} />)
        )}
      </CardContent>
    </Card>
  );
}

function SourceRow({ source }: { source: TopSource }) {
  const isUser = source.kind === 'user';
  const Icon = isUser ? UserIcon : BranchIcon;
  return (
    <div className="flex items-center gap-3">
      <span
        className={cn(
          'flex size-7 shrink-0 items-center justify-center bg-surface-2 text-text-2',
          isUser ? 'rounded-full' : 'rounded-md',
        )}
      >
        <Icon aria-hidden focusable={false} className="size-3.5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between">
          {/* `name` is a repo slug (mono reads well) or a user's email (mono looks
              off and truncates awkwardly) — only monospace the repo slug. */}
          <span className={cn('truncate text-sm text-text', !isUser && 'font-mono')}>
            {source.name}
          </span>
          <span className="text-sm font-bold text-text">
            {numberFormat.format(source.findingsCount)}
          </span>
        </div>
      </div>
    </div>
  );
}
