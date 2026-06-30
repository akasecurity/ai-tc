// Cross-view helpers for the security widget cards. Presentation only — moved
// from apps/dashboard so the OSS web-ui renders the same empty/error states.
import { cn } from '@aka/ui-kit';

export const numberFormat = new Intl.NumberFormat('en-US');

/** Reusable inline error for a widget whose data failed to load. */
export function WidgetError({ message }: { message: string }) {
  // `role="alert"` so errors surfaced after the initial render (e.g. a failed
  // apply) are announced by screen readers.
  return (
    <div role="alert" className="text-xs text-text-3">
      Couldn’t load data — {message}
    </div>
  );
}

/** Reusable inline message for a widget with no data (all-zero, no error). */
export function WidgetEmpty({ message, className }: { message: string; className?: string }) {
  // `w-full` so it spans (and centers within) a card whose content is a flex row.
  return (
    <div className={cn('w-full py-6 text-center text-xs text-text-3', className)}>{message}</div>
  );
}
