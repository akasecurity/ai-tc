import { DEFAULT_TIME_RANGE, TIME_RANGE_OPTIONS, type TimeRange } from '@akasecurity/dashboard-ui';

// The security widgets are driven by a range carried in the URL (?range=…), so a
// Server Component can read it and re-fetch per range. TimeRange is the schema's
// own type, so a parsed value passes straight through to db.security.*. Falls
// back to the default for a missing/invalid value.
export function parseRange(value: string | undefined): TimeRange {
  return TIME_RANGE_OPTIONS.some((r) => r.value === value)
    ? (value as TimeRange)
    : DEFAULT_TIME_RANGE;
}

export function rangeLabel(range: TimeRange): string {
  return TIME_RANGE_OPTIONS.find((r) => r.value === range)?.label ?? range;
}
