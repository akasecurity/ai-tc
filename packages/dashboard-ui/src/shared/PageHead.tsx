import { cn } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

const LEVEL = {
  1: { Heading: 'h1', row: 'pb-6', text: undefined, title: 'text-2xl' },
  3: { Heading: 'h3', row: 'flex-wrap pb-5', text: 'min-w-0', title: 'text-lg' },
} as const;

/** Page header: title + subtitle on the left, action controls on the right. */
export function PageHead({
  title,
  sub,
  actions,
  level = 1,
}: {
  title: string;
  /**
   * Widened from `string` so a page can emphasise part of it — the findings
   * page puts its live findings/types tally here, where the numbers carry the
   * weight and the units do not.
   */
  sub?: ReactNode;
  actions?: ReactNode;
  /**
   * `1` renders the page's own `h1`. `3` renders a smaller `h3` whose actions
   * wrap below it when space runs out, for a panel inside a titled dialog.
   */
  level?: keyof typeof LEVEL;
}) {
  const { Heading, row, text, title: titleSize } = LEVEL[level];
  return (
    <div className={cn('flex items-start justify-between gap-4', row)}>
      <div className={text}>
        <Heading className={cn('font-display font-semibold text-text', titleSize)}>{title}</Heading>
        {sub !== undefined && sub !== '' && <p className="mt-1 text-sm text-text-3">{sub}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}
