// Shared detail-pane primitives used across the findings / detections /
// data-shares drawers and the inventory file drawer. Generic (no domain
// imports) so any detail view can compose them — kept here at the package root
// rather than inside a single domain view.
import { cn } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

/** Shared section heading — exported so app-injected footers match the styling. */
export function SectionLabel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        'mb-2 block text-label font-semibold uppercase tracking-wider text-text-3',
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Label-over-value pair for detail panes (drawers, inspectors). */
export function MetaItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-label font-semibold uppercase tracking-wider text-text-3">
        {label}
      </div>
      <div className="text-ui font-medium text-text">{children}</div>
    </div>
  );
}
