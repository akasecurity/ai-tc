import { TIME_RANGE_OPTIONS, type TimeRange } from '@akasecurity/dashboard-ui';

export function rangeLabel(range: TimeRange): string {
  return TIME_RANGE_OPTIONS.find((r) => r.value === range)?.label ?? range;
}
