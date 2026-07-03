import { Card, Skeleton } from '@akasecurity/ui-kit';

import type { IconComponent } from '../lib/icons.ts';

/**
 * A stat tile: a tinted icon + label on top, with a large value below. Mirrors
 * the design's `.stat` card (18px padding, 34px icon tile, 30px display value).
 *
 * Pass `loading` to show a placeholder in place of the value while the figure is
 * being fetched — distinct from a settled-but-unknown value, which the caller
 * renders as its own `value` (e.g. an em dash on error).
 */
export function StatTile({
  icon: Icon,
  iconBg,
  iconColor,
  label,
  value,
  loading = false,
}: {
  icon: IconComponent;
  iconBg: string;
  iconColor: string;
  label: string;
  value: string;
  loading?: boolean;
}) {
  return (
    <Card className="flex flex-col gap-2.5 p-4.5 shadow-sm" aria-busy={loading || undefined}>
      <div className="flex items-center gap-2.5">
        <span
          className="grid size-8.5 shrink-0 place-items-center rounded-lg"
          style={{ background: iconBg, color: iconColor }}
        >
          <Icon aria-hidden focusable={false} className="size-4.5" />
        </span>
        <span className="text-ui font-medium text-text-2">{label}</span>
      </div>
      {loading ? (
        <Skeleton className="my-1 h-7 w-10" />
      ) : (
        <span className="font-display text-3xl font-semibold leading-none tracking-[-0.03em] text-text">
          {value}
        </span>
      )}
    </Card>
  );
}
