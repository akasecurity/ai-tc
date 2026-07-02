import type { ScanCoverageProvider } from '@akasecurity/schema';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  cn,
  Meter,
  Skeleton,
} from '@akasecurity/ui-kit';

import { COLORS } from '../lib/colors.ts';
import { Provider, PROVIDERS } from '../Provider.tsx';
import { ShieldCheckIcon } from './icons.tsx';
import { WidgetError } from './widget-shared.tsx';

/** Coverage below this percentage is shown in the high-severity color. */
const COVERAGE_WARN_THRESHOLD = 60;

export interface ScanCoverageView {
  providers: ScanCoverageProvider[];
  isLoading: boolean;
  error: string | null;
}

export function ScanCoverageCardView({
  providers,
  isLoading,
  error,
  rangeLabel,
}: ScanCoverageView & { rangeLabel: string }) {
  return (
    <Card className="flex flex-col shadow-sm">
      <CardHeader>
        <CardIcon className="bg-teal-fill text-teal">
          <ShieldCheckIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Scan coverage</CardTitle>
          <CardDescription>By provider · {rangeLabel.toLowerCase()}</CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="flex flex-col gap-2.5">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          [0, 1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-6 w-full" />)
        ) : (
          providers.map((p) => {
            const disabled = !p.supported;
            const color =
              p.coverage === 100
                ? COLORS.ok
                : p.coverage >= COVERAGE_WARN_THRESHOLD
                  ? COLORS.sevMedium
                  : COLORS.sevHigh;
            return (
              <div
                key={p.provider}
                className={cn('flex items-center gap-2.5', disabled && 'opacity-45')}
              >
                <span className={cn(disabled && 'grayscale')}>
                  <Provider id={p.provider} />
                </span>
                <span className="w-28 shrink-0 truncate text-ui text-text">
                  {PROVIDERS[p.provider].label}
                  {disabled && <span className="sr-only"> — not yet supported</span>}
                </span>
                {disabled ? (
                  // Decorative empty track — coverage is N/A, so no meter semantics.
                  <span aria-hidden className="block h-1.5 flex-1 rounded-full bg-surface-3" />
                ) : (
                  <Meter
                    value={p.coverage}
                    max={100}
                    color={color}
                    height={6}
                    aria-label={`${PROVIDERS[p.provider].label} scan coverage`}
                  />
                )}
                {disabled ? (
                  <span className="w-9 shrink-0 text-right text-label font-semibold uppercase tracking-wide text-text-3">
                    Soon
                  </span>
                ) : (
                  <span className="w-9 shrink-0 text-right text-xs font-semibold text-text-2">
                    {p.coverage}%
                  </span>
                )}
              </div>
            );
          })
        )}
      </CardContent>
    </Card>
  );
}
