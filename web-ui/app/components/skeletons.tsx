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
    // pb-6 matches the real PageHead exactly, so nothing shifts on reveal.
    <div className="flex items-start justify-between gap-4 pb-6">
      <div className="flex flex-col gap-2">
        <Skeleton className="h-7 w-44" />
        <Skeleton className="h-4 w-72" />
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

/**
 * A row of stacked stat tiles. Its two remaining callers (security, scan) stand
 * in for a band their pages do not render — every real stat strip in the
 * dashboard is the compact form above — so this reserves space for nothing
 * until those two are reconciled.
 */
export function StatStripSkeleton({ tiles = 5 }: { tiles?: number }) {
  return (
    <div className="grid grid-cols-2 gap-3 pb-4 sm:grid-cols-3 lg:grid-cols-5">
      {Array.from({ length: tiles }, (_, i) => (
        <Skeleton key={i} className="h-20" />
      ))}
    </div>
  );
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
 * The `mt-4` is what most clients carry on their own root; a page whose client
 * carries none passes `mt-0` rather than inheriting a gap the real page does
 * not have.
 */
export function MasterDetailSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('mt-4 flex min-h-0 flex-1 gap-4', className)}>
      <div className="flex w-80 shrink-0 flex-col gap-2 rounded-lg border border-border p-3">
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
