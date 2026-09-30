import type { SeveritySummaryItem } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  COMBINED_STATUS_COLUMNS,
  SPLIT_STATUS_COLUMNS,
  statusHrefKey,
} from '../../src/security/status-columns.ts';

// Every field distinct, so a column that reads the wrong one returns the wrong number.
const item: SeveritySummaryItem = {
  severity: 'high',
  count: 100,
  openAtRest: 1,
  handled: 2,
  resolved: 3,
  dismissed: 4,
  caught: 5,
};

describe('SPLIT_STATUS_COLUMNS', () => {
  it('maps each column to the field it shows and to the findings-list status it links to', () => {
    // status is what the host files a link under, so a swap here sends "Resolved" to the
    // dismissed list while every count stays right.
    expect(SPLIT_STATUS_COLUMNS.map((c) => [c.key, c.status, c.pick(item)])).toEqual([
      ['open', 'open', 1],
      ['handled', 'handled', 2],
      ['resolved', 'resolved', 3],
      ['dismissed', 'dismissed', 4],
    ]);
  });
});

describe('COMBINED_STATUS_COLUMNS', () => {
  it('has no status for the combined bucket, so nothing links from it', () => {
    expect(COMBINED_STATUS_COLUMNS.map((c) => [c.key, c.status, c.pick(item)])).toEqual([
      ['open', 'open', 1],
      ['caught', undefined, 5],
      ['dismissed', 'dismissed', 4],
    ]);
  });
});

describe('statusHrefKey', () => {
  it('keys a severity or the footer row against a column or the row total', () => {
    expect(statusHrefKey('high', 'resolved')).toBe('high:resolved');
    expect(statusHrefKey('all', 'all')).toBe('all:all');
  });
});
