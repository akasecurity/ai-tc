// Shared widget state atoms (failed-to-load + empty) reused across the
// dashboard-ui card views — security AND health — so both surfaces render the
// same error/empty states. Presentation only; the connected layer (app hook or
// server fetch) supplies the narrowed message.
import { cn } from '@akasecurity/ui-kit';

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
