import { cn, Skeleton } from '@akasecurity/ui-kit';

// Page-shaped loading placeholders for the route-level loading.tsx files. These
// are plain server-renderable markup over ui-kit's Skeleton: a loading.tsx
// renders before any data exists, so it cannot use the dashboard-ui *View
// components (they are client components taking required data props).
//
// Each loading.tsx composes these inside the same padding wrapper its page.tsx
// uses, so the skeleton occupies the layout the real page will.
//
// They live in the app rather than @akasecurity/dashboard-ui, which is where a
// shared presentational composite would normally go: what each one encodes is
// the shape of a specific app ROUTE, so a second consumer would have to adopt
// this app's page layout to reuse it. If a surface outside web-ui ever needs
// them, that is the point to move them.

/** Title + subtitle bar, with an optional right-aligned control block. */
export function PageHeadSkeleton({ actions = false }: { actions?: boolean }) {
  return (
    // Each part matches the real PageHead's, not just the padding: its `h1` is
    // `text-2xl`/32px, its `sub` is `mt-1` + `text-sm`/20px, and `pb-6` is 24 —
    // 80px in all. Summing to the same total is not enough on its own, but the
    // parts were 28 + gap-2 + 16 = 76 and every page head reveal moved 4px.
    <div className="flex items-start justify-between gap-4 pb-6">
      <div className="flex flex-col gap-1">
        <Skeleton className="h-8 w-44" />
        <Skeleton className="h-5 w-72" />
      </div>
      {actions && <Skeleton className="h-8 w-32" />}
    </div>
  );
}

/** Search box + filter controls row. */
export function ToolbarSkeleton() {
  return (
    <div className="flex items-center gap-2 pb-1">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-8 w-24" />
      <Skeleton className="h-8 w-24" />
      <Skeleton className="h-8 w-24" />
      <Skeleton className="ml-auto h-8 w-20" />
    </div>
  );
}

/** Header row plus `rows` body rows of four cells. */
export function TableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="mt-4 overflow-hidden rounded-lg border border-border">
      <div className="flex items-center gap-4 border-b border-border bg-surface-2 px-4 py-2.5">
        <Skeleton className="h-3.5 w-20" />
        <Skeleton className="h-3.5 w-40" />
        <Skeleton className="h-3.5 w-24" />
        <Skeleton className="ml-auto h-3.5 w-16" />
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="flex items-center gap-4 border-b border-border px-4 py-3 last:border-b-0"
        >
          <Skeleton className="h-5 w-16" />
          <Skeleton className="h-4 w-56" />
          <Skeleton className="h-4 w-28" />
          <Skeleton className="ml-auto h-4 w-14" />
        </div>
      ))}
    </div>
  );
}

/**
 * The compact single-Card summary strip (SummaryStripView), as Activity,
 * Detections and Policies head their master/detail with. `h-12.5` is that
 * Card's box exactly — 1px border + py-2.5 + a size-7 icon tile + py-2.5 + 1px
 * border = 50px — so nothing shifts on reveal. It carries no margin of its own,
 * matching the strip: the caller passes whatever its page spends there.
 */
export function CompactStatStripSkeleton({ className }: { className?: string }) {
  return <Skeleton className={cn('h-12.5 w-full shrink-0 rounded-xl', className)} />;
}

/** Grid of card-shaped blocks. */
export function CardGridSkeleton({ cards = 3, className }: { cards?: number; className?: string }) {
  return (
    <div className={cn('grid grid-cols-1 gap-4 lg:grid-cols-3', className)}>
      {Array.from({ length: cards }, (_, i) => (
        <Skeleton key={i} className="h-56" />
      ))}
    </div>
  );
}

/** A single full-width card block. */
export function CardSkeleton({ className }: { className?: string }) {
  return <Skeleton className={cn('h-64 w-full', className)} />;
}

/**
 * Left list column + right detail pane, for the master/detail pages. Fills its
 * parent, which the page's own wrapper constrains (`flex h-full min-h-0`).
 *
 * `listWidth` is the real list column's width for THIS route — they differ
 * (activity and inventory `w-85`, detections `w-88`, policies `lg:w-80`), and a
 * skeleton one size for all of them slides the detail pane sideways on reveal.
 *
 * `stacksBelowLg` mirrors a client that is ONE stacked column until `lg` and two
 * side by side after — Policies alone, whose root is `grid-cols-1 …
 * lg:grid-cols-[320px_1fr]`. Without it the skeleton paints a fixed-width list
 * beside a detail pane at every width, and below 1024px the reveal is a
 * relayout rather than a slide. Such a route spells its width with the same
 * `lg:` prefix its client uses, so the stacked column stretches full width
 * below the breakpoint and takes the width only where the column exists.
 *
 * It carries no top margin: every client root above one of these starts flush,
 * and the gap over a master/detail comes from the strip's own `mb-3`.
 */
export function MasterDetailSkeleton({
  listWidth = 'w-85',
  stacksBelowLg = false,
}: {
  listWidth?: string;
  stacksBelowLg?: boolean;
}) {
  return (
    <div
      className={cn(
        'flex flex-1 gap-4',
        // Mirrors PoliciesClient's own `min-h-128 … lg:min-h-0` cap.
        stacksBelowLg ? 'min-h-128 flex-col lg:min-h-0 lg:flex-row' : 'min-h-0',
      )}
    >
      <div
        className={cn(
          'flex shrink-0 flex-col gap-2 rounded-lg border border-border p-3',
          listWidth,
        )}
      >
        {Array.from({ length: 8 }, (_, i) => (
          <Skeleton key={i} className="h-14" />
        ))}
      </div>
      <div className="min-h-0 flex-1 rounded-lg border border-border p-4">
        <Skeleton className="h-8 w-64" />
        <div className="mt-4 grid grid-cols-2 gap-3">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-10" />
          ))}
        </div>
        <Skeleton className="mt-6 h-72 w-full" />
      </div>
    </div>
  );
}
