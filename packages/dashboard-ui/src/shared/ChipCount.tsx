import { formatNumber } from '../lib/numberFormat.ts';

/**
 * The count a filter chip shows beside its label, formatted in `locale`.
 *
 * The separator is `sr-only` text rather than the chip's flex gap alone: a gap
 * is layout, not text, so it is not part of the button's accessible name, and
 * without it the chip reads as one run-together word (`Exposed4`). It sits
 * inside the count rather than beside it, so the chip's spacing does not depend
 * on `sr-only` being out of flow.
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
