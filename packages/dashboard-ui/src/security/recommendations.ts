// Pure recommendation/health builders over the local store's finding views —
// NO React, no DOM. Consumed three ways: the Recommended Actions
// card (via the package root), a dashboard, and the CLI's ink TUI
// (via the `@akasecurity/dashboard-ui/recommendations` subpath export, which keeps
// the React view tree out of the CLI bundle). Ported from the plugin's
// render.ts — the maths must stay in step so every surface agrees on the
// numbers.
import type { FindingView, HealthSummary, RecommendedAction, Severity } from '@akasecurity/schema';

const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// Plain-language next step per detection category, shown by the Recommend view.
const ADVICE: Record<string, string> = {
  secret:
    'Rotate the exposed credentials and move them out of prompts (secrets manager / env vars).',
  pii: 'Remove or mask personal data before it reaches the model.',
  financial: 'Strip card and account numbers; share only non-sensitive references.',
  phi: 'Remove protected health information — it should never reach an external model.',
  code_context: 'Confirm this proprietary code context is safe to share.',
  code_flaw:
    'Review the flagged pattern and apply the secure alternative (parameterized queries, safe deserializers, etc.).',
  config:
    'Review the setting — a hook conflict or an egress change applies to every session that follows.',
  custom: 'Review against your organization’s custom policy.',
};

const REC_TEMPLATE: Record<string, { title: string; action: string }> = {
  secret: { title: 'Exposed secret detected', action: 'Rotate' },
  pii: { title: 'Personal data in a prompt', action: 'Remove' },
  financial: { title: 'Financial data detected', action: 'Strip' },
  phi: { title: 'Health information detected', action: 'Remove' },
  code_context: { title: 'Proprietary code shared', action: 'Review' },
  code_flaw: { title: 'Insecure code pattern', action: 'Fix' },
  config: { title: 'Weakened configuration', action: 'Review' },
  custom: { title: 'Custom policy match', action: 'Review' },
};

const MAX_RECOMMENDATIONS = 10;

// Derived posture score (0–100). HEURISTIC — blends category coverage and the
// share of findings that were acted on (block/redact/warn). Mirrors render.ts.
export function healthScore(summary: HealthSummary): number {
  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledRatio = summary.findings === 0 ? 1 : handled / summary.findings;
  return Math.round(100 * (0.6 * summary.coverage + 0.4 * handledRatio));
}

export interface FindingStatus {
  score: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  openFindings: number;
}

export function findingStatus(summary: HealthSummary): FindingStatus {
  return {
    score: healthScore(summary),
    unreviewed: { ...summary.bySeverity },
    openFindings: summary.findings,
  };
}

interface Bucket {
  category: string;
  /**
   * The named rule's tally ACROSS the input, which is what the label reports and
   * what the link lands on. Not the rule's tally within this bucket's category: the
   * findings page cannot filter by category, so a per-category count would name a
   * number the destination never shows.
   */
  count: number;
  /** The whole category's tally, which is what ranks one bucket against another. */
  categoryCount: number;
  severity: string;
  weight: number;
  ruleId: string;
}

/**
 * The three fields the prioritization reads. Narrower than `FindingView` so a
 * caller holding only a rollup row can pass it — a full `FindingView[]` still
 * satisfies it.
 */
export type RecommendationInput = Pick<FindingView, 'category' | 'severity' | 'ruleId'> & {
  /**
   * How many findings this row stands for. Absent means one, so a caller holding
   * raw findings passes them unchanged; a caller holding a SQL rollup passes one
   * row per group and the tallies below still come out right.
   */
  count?: number;
};

/**
 * One bucket per detection category, keyed to its most-severe rule.
 *
 * `count` is that RULE's tally, not the category's. Both rendered shapes label a
 * bucket `"<ruleId> · <count> findings"`, so a category-wide count would pair one
 * rule's name with another number — and on the security card that number is now a
 * link target, where the discrepancy becomes reachable rather than merely odd.
 * Counting per rule is what makes the label agree with what the link lands on.
 */
function bucketize(findings: RecommendationInput[]): Bucket[] {
  // Per-rule tallies first: a bucket's count is only known once its most-severe
  // rule is, which is not decided until the whole pass is done.
  //
  // Keyed by RULE alone, deliberately, because the label and the link must describe
  // the same set and the findings page has no category dimension — it filters on
  // `ruleId`. Counting per (category, rule) instead would render two rows for a rule
  // whose category moved between pack versions, showing 5 and 3, both linking to a
  // list of 8.
  //
  // So the number is the rule's, and the category is only how the row was chosen and
  // titled. The comment on `count` below says which of the two it reports.
  const byRule = new Map<string, number>();
  const buckets = new Map<string, Bucket>();
  for (const f of findings) {
    const n = f.count ?? 1;
    byRule.set(f.ruleId, (byRule.get(f.ruleId) ?? 0) + n);
    const b = buckets.get(f.category) ?? {
      category: f.category,
      count: 0,
      categoryCount: 0,
      severity: f.severity,
      weight: 0,
      ruleId: f.ruleId,
    };
    b.categoryCount += n;
    const w = SEVERITY_WEIGHT[f.severity] ?? 0;
    if (w > b.weight) {
      b.weight = w;
      b.severity = f.severity;
      b.ruleId = f.ruleId;
    }
    buckets.set(f.category, b);
  }
  for (const b of buckets.values()) b.count = byRule.get(b.ruleId) ?? 0;
  // Ranked on the CATEGORY's volume, not the named rule's. The label reports one
  // rule so it can agree with the link, but ordering is about which kind of
  // exposure matters most — ranking on the rule would sort a category holding
  // hundreds of findings below one holding three.
  return [...buckets.values()]
    .sort((a, b) => b.weight - a.weight || b.categoryCount - a.categoryCount)
    .slice(0, MAX_RECOMMENDATIONS);
}

export interface Recommendation {
  severity: string;
  title: string;
  description: string;
  context: string;
  action: string;
}

/** The TUI/transcript shape: plain strings, rendered as text. */
export function buildRecommendations(findings: RecommendationInput[]): Recommendation[] {
  return bucketize(findings).map((b) => {
    const t = REC_TEMPLATE[b.category] ?? { title: `${b.category} finding`, action: 'Review' };
    return {
      severity: b.severity,
      title: t.title,
      description: ADVICE[b.category] ?? 'Review this finding against your policy.',
      context: `${b.ruleId} · ${String(b.count)} finding${b.count === 1 ? '' : 's'}`,
      action: t.action,
    };
  });
}

// FindingView.severity is a plain string at this layer; the RecommendedAction
// contract wants the closed Severity enum. Anything unrecognized renders low.
function toSeverity(severity: string): Severity {
  return severity === 'critical' || severity === 'high' || severity === 'medium' ? severity : 'low';
}

/** How a host turns the rule a recommendation names into a destination. */
export interface RecommendedActionOptions {
  /**
   * The findings URL for `ruleId`. Host-supplied so this package mints no routes
   * and stays router-agnostic.
   *
   * Omitted, or returning undefined, leaves the action with NO href, and the card
   * renders it disabled. That is deliberate: a row reads "<rule> · N findings", so
   * a generic fallback to the unfiltered list would name a number the destination
   * does not show — the same label/destination mismatch the per-rule count exists
   * to prevent.
   */
  hrefForRule?: (ruleId: string) => string | undefined;
}

/**
 * The same prioritization as {@link buildRecommendations}, shaped for the
 * security page's Recommended Actions card (the schema RecommendedAction
 * contract). Actions navigate to the findings page — the local store has no
 * server-side apply endpoint.
 */
export function buildRecommendedActions(
  findings: RecommendationInput[],
  options: RecommendedActionOptions = {},
): RecommendedAction[] {
  return bucketize(findings).map((b) => {
    const href = options.hrefForRule?.(b.ruleId);
    const t = REC_TEMPLATE[b.category] ?? { title: `${b.category} finding`, action: 'Review' };
    return {
      id: `local-${b.category}`,
      category: b.category,
      severity: toSeverity(b.severity),
      title: t.title,
      description: ADVICE[b.category] ?? 'Review this finding against your policy.',
      subjects: [
        {
          type: 'rule' as const,
          id: b.ruleId,
          label: `${b.ruleId} · ${String(b.count)} finding${b.count === 1 ? '' : 's'}`,
        },
      ],
      action: {
        mode: 'navigate' as const,
        type: 'review_findings',
        label: t.action,
        ...(href === undefined ? {} : { href }),
      },
    };
  });
}
