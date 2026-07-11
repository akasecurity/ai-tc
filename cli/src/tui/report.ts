// Pure report builders for the TUI screens — the colour twin's data layer.
//
// The recommendation/health maths lives in @akasecurity/dashboard-ui's pure
// `recommendations` module (imported via its subpath export so the React view
// tree never enters the CLI bundle) — one implementation shared with the web-ui
// Recommended Actions card, so every surface agrees on the numbers. What stays
// here is the TUI-only report assembly (gauges, weekday labels).
import type { FindingStatus, Recommendation } from '@akasecurity/dashboard-ui/recommendations';
import {
  buildRecommendations,
  findingStatus,
  healthScore,
} from '@akasecurity/dashboard-ui/recommendations';
import type { DayActivity, FindingView, HealthSummary } from '@akasecurity/schema';

export type { FindingStatus, Recommendation };
export { buildRecommendations, findingStatus, healthScore };

export interface HealthGauge {
  label: string;
  score: number; // 0–100
  note: string;
  outOf100?: boolean;
}

export interface HealthDay {
  label: string; // "Mon"
  total: number;
  redacted: number;
  warned: number;
  blocked: number;
}

export interface HealthReport {
  title: string;
  gauges: HealthGauge[];
  openFindings: number;
  scanCoverage: number; // 0..1
  week: HealthDay[];
  weekFindings: number;
  recommendCount: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  score: number;
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const;

function weekday(isoDay: string): string {
  const date = new Date(`${isoDay}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? isoDay : (WEEKDAYS[date.getUTCDay()] ?? isoDay);
}

export function buildHealthReport(
  summary: HealthSummary,
  findings: FindingView[],
  activity: DayActivity[],
): HealthReport {
  const status = findingStatus(summary);

  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledPct = summary.findings === 0 ? 100 : Math.round((handled / summary.findings) * 100);
  const coveragePct = Math.round(summary.coverage * 100);

  const gauges: HealthGauge[] = [
    {
      label: 'Overall',
      score: status.score,
      note: `${String(summary.findings)} finding${summary.findings === 1 ? '' : 's'} total`,
      outOf100: true,
    },
    { label: 'Coverage', score: coveragePct, note: 'categories under policy' },
    {
      label: 'Handled',
      score: handledPct,
      note:
        summary.findings === 0
          ? 'no findings yet'
          : `${String(handled)}/${String(summary.findings)} acted on`,
    },
  ];

  const week: HealthDay[] = activity.map((d) => ({
    label: weekday(d.day),
    total: d.total,
    redacted: d.redacted,
    warned: d.warned,
    blocked: d.blocked,
  }));

  return {
    title: 'Setup health — local Claude Code deployment',
    gauges,
    openFindings: status.openFindings,
    scanCoverage: summary.coverage,
    week,
    weekFindings: week.reduce((n, d) => n + d.total, 0),
    recommendCount: buildRecommendations(findings).length,
    unreviewed: status.unreviewed,
    score: status.score,
  };
}
