// The one presentational form for a resolved vault pointer, shared by every
// surface that shows one. Three states, decided purely by the props:
//   value present    → the raw value
//   descriptor only  → the masked preview (no raw available)
//   neither          → "[unavailable]"
// Props-driven and render-only: the caller does the de-referencing (and takes
// the audit row); nothing here fetches or resolves anything.
import type { PointerDescriptor } from '@akasecurity/schema';
import { cn } from '@akasecurity/ui-kit';

import { ShowMore } from '../findings/ShowMore';

// The descriptor slice this view needs — a structural subset of
// PointerDescriptor, so a full descriptor passes straight through.
type ScrubbedDescriptor = Pick<PointerDescriptor, 'category' | 'maskedMatch'> &
  Partial<Pick<PointerDescriptor, 'provider' | 'occurrences'>>;

export function ScrubbedValue({
  value,
  descriptor,
  className,
}: {
  value: string | null;
  descriptor: ScrubbedDescriptor | null;
  className?: string;
}) {
  if (value === null && descriptor === null) {
    return (
      <span data-slot="scrubbed-value" className={cn('text-ui text-text-3', className)}>
        [unavailable]
      </span>
    );
  }
  return (
    <span
      data-slot="scrubbed-value"
      className={cn('inline-flex flex-wrap items-center gap-2', className)}
    >
      {value !== null ? (
        <code className="break-all font-mono text-ui text-text">
          <ShowMore value={value} />
        </code>
      ) : (
        <code className="break-all font-mono text-ui text-text-2">
          <ShowMore value={descriptor?.maskedMatch ?? ''} />
        </code>
      )}
    </span>
  );
}
