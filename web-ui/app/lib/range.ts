import { DEFAULT_TIME_RANGE, TIME_RANGES, type TimeRange } from '@akasecurity/dashboard-ui';

// The security widgets are driven by a range carried in the URL (?range=…), so a
// Server Component can read it and re-fetch per range. TimeRange values are the
// same set as @akasecurity/schema's SecurityRange (7d/30d/3m/6m), so they pass straight
// through to db.security.*. Falls back to the default for a missing/invalid value.
export function parseRange(value: string | undefined): TimeRange {
  return TIME_RANGES.some((r) => r.value === value) ? (value as TimeRange) : DEFAULT_TIME_RANGE;
}

export function rangeLabel(range: TimeRange): string {
  return TIME_RANGES.find((r) => r.value === range)?.label ?? range;
}
