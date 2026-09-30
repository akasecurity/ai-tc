import type { FindingStatus, Severity, SeveritySummaryItem } from '@akasecurity/schema';

export interface StatusColumn {
  key: string;
  label: string;
  /** The findings-list status this column filters by; absent for the combined bucket. */
  status?: FindingStatus;
  pick: (s: SeveritySummaryItem) => number;
}

const OPEN: StatusColumn = {
  key: 'open',
  label: 'Open',
  status: 'open',
  pick: (s) => s.openAtRest ?? 0,
};
const DISMISSED: StatusColumn = {
  key: 'dismissed',
  label: 'Dismissed',
  status: 'dismissed',
  pick: (s) => s.dismissed ?? 0,
};

/** The columns for a response that carries the handled/resolved split. */
export const SPLIT_STATUS_COLUMNS: StatusColumn[] = [
  OPEN,
  { key: 'handled', label: 'Handled', status: 'handled', pick: (s) => s.handled ?? 0 },
  { key: 'resolved', label: 'Resolved', status: 'resolved', pick: (s) => s.resolved ?? 0 },
  DISMISSED,
];

/** The columns for a response that carries `caught` but not its two halves. */
export const COMBINED_STATUS_COLUMNS: StatusColumn[] = [
  OPEN,
  { key: 'caught', label: 'Caught', pick: (s) => s.caught ?? 0 },
  DISMISSED,
];

/**
 * The key a host files a status-cell link under in `SeverityCardView`'s
 * `statusHrefs`: a severity (or `all` for the footer row) against a status column
 * (or `all` for the row total).
 */
export function statusHrefKey(row: Severity | 'all', column: string): string {
  return `${row}:${column}`;
}
