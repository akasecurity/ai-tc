// Pure recommendation/health builders over the local store's finding views —
// NO React, no DOM. Consumed three ways: the Recommended Actions
// card (via the package root), a dashboard, and the CLI's ink TUI
// (via the `@akasecurity/dashboard-ui/recommendations` subpath export, which keeps
// the React view tree out of the CLI bundle). Ported from the plugin's
// render.ts — the maths must stay in step so every surface agrees on the
// numbers.
import type { HealthSummary, RecommendedAction, Severity } from '@akasecurity/schema';
import type { RecommendationInput } from '@akasecurity/schema';
import { bucketizeRecommendations, recommendationCopy } from '@akasecurity/schema';

// Re-exported so this module's public surface is unchanged by the move: the CLI
// imports them from the `./recommendations` subpath, and the package index from
// here.
export type { Recommendation, RecommendationInput } from '@akasecurity/schema';
export { buildRecommendations, SEVERITY_WEIGHT } from '@akasecurity/schema';

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
  return bucketizeRecommendations(findings).map((b) => {
    const href = options.hrefForRule?.(b.ruleId);
    const copy = recommendationCopy(b.category);
    return {
      id: `local-${b.category}`,
      category: b.category,
      severity: toSeverity(b.severity),
      title: copy.title,
      description: copy.advice,
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
        label: copy.action,
        ...(href === undefined ? {} : { href }),
      },
    };
  });
}
