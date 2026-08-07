'use client';

import { Button } from '@akasecurity/ui-kit';
import { useState } from 'react';

// maskMatch keeps most values short — a fixed 8 characters, or a short masked
// email — but a URL-credential secret (e.g. a database connection string)
// reveals its host unmasked and can run long. Collapse those behind a toggle
// so one finding doesn't blow out the row.
const COLLAPSE_LENGTH = 80;

/** A finding's masked value, truncated behind a "Show more" toggle past
 * COLLAPSE_LENGTH characters. */
export function ShowMore({
  value,
  className,
  charCount = COLLAPSE_LENGTH,
}: {
  value: string;
  className?: string;
  charCount?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const isLong = value.length > charCount;
  const shown = !isLong || expanded ? value : `${value.slice(0, charCount)}…`;

  return (
    <div className={className}>
      <span className="wrap-anywhere">{shown}</span>
      {isLong && (
        <Button
          variant="link"
          tone="primary"
          size="sm"
          className="ml-1 font-ui"
          aria-expanded={expanded}
          onClick={(e) => {
            e.stopPropagation();
            setExpanded((v) => !v);
          }}
        >
          {expanded ? 'Show less' : 'Show more'}
        </Button>
      )}
    </div>
  );
}
