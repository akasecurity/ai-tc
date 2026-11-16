import { formatNumber } from '../lib/numberFormat.ts';

/**
 * The count's styling on a filter pill: the credentials status chips and the
 * inventory table's pills, which are drawn to match each other.
 */
export const PILL_COUNT_CLASS = 'tabular-nums opacity-70';

/** The count's styling on a list's compact filter chips (detections, finding types). */
export const LIST_FILTER_COUNT_CLASS = 'text-label font-bold opacity-70';

/**
 * A count that a control shows beside its label, formatted in `locale`: a
 * filter chip or pill, a menu option, a badge on a trigger, a nav row, a list
 * row.
 *
 * The separator is `sr-only` text rather than the control's flex gap alone: a
 * gap is layout, not text, so it is not part of the control's accessible name,
 * and without it the control reads as one run-together word (`Exposed4`). It
 * sits inside the count rather than beside it, so the control's spacing does
 * not depend on `sr-only` being out of flow.
 */
export function ChipCount({
  value,
  locale,
  className,
}: {
  value: number;
  /** The locale the count is formatted in, as the host resolved it. */
  locale: string;
  /** The count's styling, which belongs to the control it sits in. */
  className?: string | undefined;
}) {
  return (
    <span className={className}>
      <span className="sr-only">, </span>
      {formatNumber(value, locale)}
    </span>
  );
}
