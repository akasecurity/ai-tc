// Activity display formatting — semantic /v1/activity values in, display strings
// out. Lives with the views (not the apps) so the Vite dashboard and the OSS
// web-ui render identical labels. The API is deliberately semantic (ISO
// timestamps + raw integer counts, no pre-formatted strings); day grouping,
// time-of-day, duration, and token humanization are all derived here.
import type { ActivitySessionSummary, SessionStatus, TokenRollup } from '@akasecurity/schema';
import { formatTokenCount } from '@akasecurity/schema';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const DAY_MS = 86_400_000;

/** Sessions bucketed under one day heading, preserving the input order. */
export interface SessionDay {
  day: string;
  items: ActivitySessionSummary[];
}

/** Local-midnight epoch millis for a date — the calendar-day boundary in the
 * viewer's timezone (so a date can't shift a day in a negative-offset zone). */
function startOfLocalDay(d: Date): number {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/**
 * Day-group heading for a session, in the viewer's timezone: `Today` /
 * `Yesterday` / `Mon, Jun 8`. Computed from `startedAt` client-side — the API
 * returns the timestamp, never the label (see the activity API spec's "Day
 * grouping is computed client-side" note).
 */
export function dayLabel(iso: string, now: Date = new Date()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const diffDays = Math.round((startOfLocalDay(now) - startOfLocalDay(d)) / DAY_MS);
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  return `${WEEKDAYS[d.getDay()] ?? ''}, ${MONTHS[d.getMonth()] ?? ''} ${String(d.getDate())}`;
}

const TIME_OF_DAY = new Intl.DateTimeFormat('en-US', {
  hour: 'numeric',
  minute: '2-digit',
  hour12: true,
});

/** Session start time, viewer-local: `9:14 AM`. */
export function startLabel(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? '' : TIME_OF_DAY.format(t);
}

const EVENT_TIME = new Intl.DateTimeFormat('en-US', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/** Timeline event wall-clock time, viewer-local: `09:14:02`. */
export function eventTime(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? '' : EVENT_TIME.format(t);
}

/**
 * Human duration derived from the timestamp pair: `46m` / `1h 12m`. An open
 * (`active`) session has no `endedAt`, so it measures against `now` and gets a
 * `· live` suffix — matching the design's "46m · live" pill.
 */
export function durationLabel(
  startedAt: string,
  endedAt: string | null,
  status: SessionStatus,
  now: number = Date.now(),
): string {
  const start = Date.parse(startedAt);
  if (Number.isNaN(start)) return '';
  const end = endedAt ? Date.parse(endedAt) : now;
  const totalMin = Math.max(0, Math.round((end - start) / 60_000));
  const hours = Math.floor(totalMin / 60);
  const mins = totalMin % 60;
  const span = hours > 0 ? `${String(hours)}h ${String(mins)}m` : `${String(mins)}m`;
  return status === 'active' ? `${span} · live` : span;
}

/**
 * Cache-hit share of the session's read tokens: cached reads over cached reads
 * plus fresh input — the `71%` cache pill. 0-safe (a session with no token
 * activity reads 0).
 */
export function cacheHitPct(tokens: TokenRollup): number {
  const denom = tokens.cacheRead + tokens.inputTokens;
  return denom > 0 ? Math.round((100 * tokens.cacheRead) / denom) : 0;
}

/** Compact token count for the detail band — the shared @akasecurity/schema
 * humanizer (`128400` → `128.4k`, rolling k→M→B) so every surface reads
 * identically. */
export function tokenLabel(n: number): string {
  return formatTokenCount(n);
}

// USD + cost-total formatters are the SHARED @akasecurity/schema ones
// (re-exported so the Activity views keep importing from './format.ts'), so the
// Activity page, the plugin's `/aka:tokens`, and the CLI/TUI print the same figure
// AND the same qualifier convention (`$X` / `≥ $X`) — no local `~`/`—` drift.
export { formatCostTotal, formatUsd } from '@akasecurity/schema';

/**
 * Buckets a flat, most-recent-first session list into day groups, preserving
 * order — the server returns a flat `items[]`, the day headings are a view
 * concern (see `dayLabel`). A session with an unparseable `startedAt` falls
 * into an empty-label bucket rather than being dropped.
 */
export function groupSessionsByDay(
  items: ActivitySessionSummary[],
  now: Date = new Date(),
): SessionDay[] {
  const groups: SessionDay[] = [];
  for (const session of items) {
    const day = dayLabel(session.startedAt, now);
    let group = groups.find((g) => g.day === day);
    if (!group) {
      group = { day, items: [] };
      groups.push(group);
    }
    group.items.push(session);
  }
  return groups;
}
