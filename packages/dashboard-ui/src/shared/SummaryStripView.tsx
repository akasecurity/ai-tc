// The compact summary strip: one Card with inline stats separated by dividers.
//
// It lives in shared/ rather than under one feature folder because Activity,
// Detections and Policies all head their master/detail with it. The strip is
// chrome above a list, so its whole point is to cost as little vertical space as
// a row of stats can: it measures 50px, and the height it does not spend is
// height the list underneath gets instead.
import { Card, cn, Skeleton, type Tone, TONE_PARTS } from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import type { IconComponent } from '../lib/icons.ts';

/**
 * A stat's tonal family. Naming the family rather than its two class strings is
 * what stops the halves being crossed: a `-ink` foreground belongs to exactly
 * one `-fill` tint, and spelling both by hand at each call site compiles and
 * renders whichever pair is typed.
 *
 * It is a subset of `@akasecurity/ui-kit`'s `Tone` rather than a vocabulary of
 * its own — a second registry for the same families is how one family came to
 * mean `surface-2` in one place and `surface-3` in another. `Extract` narrows
 * the union to the families the strip actually uses; note it does NOT reject an
 * unknown name, which evaluates to `never` here and only errors at a call site.
 */
export type StatTone = Extract<Tone, 'primary' | 'muted' | 'violet' | 'ok' | 'critical' | 'teal'>;

export interface SummaryStatItem {
  icon: IconComponent;
  value: string | number;
  label: string;
  tone: StatTone;
}

// One stat. The value and its label sit on a single baseline rather than stacked:
// the strip is chrome above a list, so its height is space that list does not
// get, and a label long enough to wrap is truncated with the full text on hover
// rather than growing the row.
//
// While loading, the icon and label stay and only the VALUE is withheld. That is
// the half the read has not answered yet; withholding the label too would leave
// an anonymous grey bar that no longer says what is loading.
function SummaryStat({
  icon: Icon,
  value,
  label,
  tone,
  isLoading,
}: SummaryStatItem & { isLoading: boolean }) {
  const { text, fill } = TONE_PARTS[tone];
  return (
    <div data-slot="summary-stat" className="flex min-w-0 flex-1 items-center gap-2 px-4">
      <span
        data-slot="summary-stat-icon"
        className={cn('grid size-7 shrink-0 place-items-center rounded-lg', fill, text)}
      >
        <Icon aria-hidden focusable={false} className="size-3.5" />
      </span>
      {/* `overflow-hidden` bounds the pair to its own cell. The value below does
          not wrap and does not shrink, so without a clip here a value wider than
          its 1/n share would paint over the divider and the next cell's icon. */}
      <div
        className="flex min-w-0 items-baseline gap-1.5 overflow-hidden"
        title={isLoading ? label : `${String(value)} ${label}`}
      >
        {isLoading ? (
          <Skeleton className="h-4 w-10 shrink-0" />
        ) : (
          /* The value never wraps: one carrying a space (Detections' "7 / 7")
             has a one-character min-content width, so wrapping would break it
             across lines and grow the whole Card past the one row its height is
             declared to be. It ellipsizes rather than clipping, because the two
             truncations are not equally safe — a cut label ellipsizes and keeps
             the rest in the `title`, while a cut NUMBER reads as a different,
             smaller number ("1,284 / 1,3" is a plausible value). The label
             still gives way first: its shrink weight below is what decides the
             order, not a refusal to shrink here. */
          <span className="min-w-0 truncate font-display text-lg font-semibold leading-none tabular-nums text-text">
            {value}
          </span>
        )}
        {/* Absorbs essentially all of the shrink, so the value only ellipsizes
            once the label has collapsed — it is the half with a hover fallback. */}
        <span className="shrink-[9999] truncate text-xs text-text-3">{label}</span>
      </div>
    </div>
  );
}

export function SummaryStripView({
  items,
  isLoading,
  className,
}: {
  items: SummaryStatItem[];
  /**
   * Withholds each stat's VALUE while the read is in flight. The items are still
   * passed and still rendered, so the strip keeps saying what is loading and
   * cannot change its cell count — or its width-per-cell — on reveal.
   *
   * That is a claim about the CELLS, not about what sits inside them: the value
   * placeholder is a fixed width while settled values are not, so the space left
   * for the label — and therefore where the label truncates — can still move on
   * reveal. It is bounded to one cell and cannot affect the strip's height,
   * which the `size-7` icon tile governs either way.
   */
  isLoading: boolean;
  /**
   * Overrides the default `mb-3`. The gap under the strip is the one thing a
   * page and its skeleton must agree on exactly — spelling it at both call
   * sites made that agreement a convention; carrying it here makes it the
   * default they share. `CompactStatStripSkeleton` carries the same one.
   */
  className?: string | undefined;
}) {
  return (
    <Card
      className={cn('mb-3 flex shrink-0 items-stretch overflow-hidden py-2.5 shadow-sm', className)}
      aria-busy={isLoading}
    >
      {items.map((item, i) => (
        <Fragment key={item.label}>
          {i > 0 && <span className="w-px shrink-0 self-stretch bg-text/6" />}
          <SummaryStat {...item} isLoading={isLoading} />
        </Fragment>
      ))}
    </Card>
  );
}
