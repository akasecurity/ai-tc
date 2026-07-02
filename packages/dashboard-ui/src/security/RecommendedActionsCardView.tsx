'use client';

import type { RecommendedAction, Severity } from '@akasecurity/schema';
import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  cn,
  Skeleton,
  Tag,
} from '@akasecurity/ui-kit';

import type { IconComponent } from '../lib/icons.ts';
import {
  AlertOctagonIcon,
  ExternalShareIcon,
  RedactIcon,
  SlashCircleIcon,
  SparklesIcon,
} from '../shared/icons.tsx';
import { WidgetError } from './widget-shared.tsx';

type RecommendationTone = 'critical' | 'primary' | 'teal';

const TONE_TILE: Record<RecommendationTone, string> = {
  critical: 'bg-sev-critical-fill text-sev-critical',
  primary: 'bg-primary-tint text-primary',
  teal: 'bg-teal-fill text-teal',
};

// `category` is an extensible string; map the known ones to a tile icon, falling
// back to a generic alert for any new category.
const RECOMMENDATION_ICON: Record<string, IconComponent> = {
  block_credentials: SlashCircleIcon,
  redact_pii: RedactIcon,
  review_external_share: ExternalShareIcon,
};

// Tile color follows the recommendation's severity (a closed enum, robust to new
// categories) and reproduces the original per-category design.
const SEVERITY_TONE: Record<Severity, RecommendationTone> = {
  critical: 'critical',
  high: 'primary',
  medium: 'teal',
  low: 'teal',
};

// Callbacks come from the connected layer (a Server Action in the web-ui
// dashboard), so the view stays data-source-blind.
export interface RecommendedActionsView {
  items: RecommendedAction[];
  isLoading: boolean;
  error: string | null;
  applyAction: (id: string) => void;
  dismissAction: (id: string) => void;
  isMutating: boolean;
  mutationError: string | null;
}

export function RecommendedActionsCardView({
  items,
  isLoading,
  error,
  applyAction,
  dismissAction,
  isMutating,
  mutationError,
}: RecommendedActionsView) {
  return (
    <Card className="flex flex-col shadow-sm">
      <CardHeader>
        <CardIcon className="bg-primary-tint text-primary">
          <SparklesIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Recommended actions</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading…' : `${String(items.length)} prioritized for your environment`}
          </CardDescription>
        </CardHeading>
        <CardAction>
          <Button variant="ghost" tone="primary" size="sm">
            View all
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent aria-busy={isLoading}>
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <div className="flex flex-col gap-3 py-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="py-6 text-center text-xs text-text-3">No recommendations right now.</div>
        ) : (
          <>
            {mutationError && <WidgetError message={mutationError} />}
            {items.map((a, i) => {
              const Icon = RECOMMENDATION_ICON[a.category] ?? AlertOctagonIcon;
              return (
                <div
                  key={a.id}
                  className={cn(
                    'flex gap-3 py-3',
                    i < items.length - 1 && 'border-b border-text/6',
                  )}
                >
                  <span
                    className={cn(
                      'flex size-8 shrink-0 items-center justify-center rounded-lg',
                      TONE_TILE[SEVERITY_TONE[a.severity]],
                    )}
                  >
                    <Icon aria-hidden focusable={false} className="size-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-text">{a.title}</div>
                    <div className="mt-0.5 text-xs leading-relaxed text-text-2">
                      {a.description}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {a.subjects.map((s) => (
                        <Tag key={`${s.type}_${s.id}`}>{s.label}</Tag>
                      ))}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1.5">
                    {a.action.mode === 'apply' ? (
                      <Button
                        variant="solid"
                        tone="primary"
                        size="sm"
                        disabled={isMutating}
                        onClick={() => {
                          applyAction(a.id);
                        }}
                      >
                        {a.action.label}
                      </Button>
                    ) : a.action.href ? (
                      <Button asChild variant="solid" tone="primary" size="sm">
                        <a href={a.action.href}>{a.action.label}</a>
                      </Button>
                    ) : (
                      // `href` is optional; a navigate action without one has nowhere
                      // to go, so show it disabled rather than as a dead link.
                      <Button variant="solid" tone="primary" size="sm" disabled>
                        {a.action.label}
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={isMutating}
                      onClick={() => {
                        dismissAction(a.id);
                      }}
                    >
                      Dismiss
                    </Button>
                  </div>
                </div>
              );
            })}
          </>
        )}
      </CardContent>
    </Card>
  );
}
