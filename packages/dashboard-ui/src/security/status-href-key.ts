import type { Severity } from '@akasecurity/schema';

// Deliberately NOT in SeverityCardView.tsx: that file is a client module, and a
// server component (the host page) cannot call a function exported from one.

/**
 * The key a host files a status-cell link under in `SeverityCardView`'s
 * `statusHrefs`: a severity (or `all` for the footer row) against a status column
 * (or `all` for the row total).
 */
export function statusHrefKey(row: Severity | 'all', column: string): string {
  return `${row}:${column}`;
}
