// The card's view of the recommendation rollup — NO React, no DOM.
//
// The maths lives in `@akasecurity/schema`, shared with `aka tui` and the three
// plugins; what is left here is `buildRecommendedActions`, which shapes a bucket
// into the schema `RecommendedAction` contract the card renders and takes the
// host's href builder. Reached two ways: the package root, and the
// `@akasecurity/dashboard-ui/recommendations` subpath the CLI uses to keep the
// React view tree out of its bundle.
import type { RecommendationInput, RecommendedAction, Severity } from '@akasecurity/schema';
import { bucketizeRecommendations, recommendationCopy } from '@akasecurity/schema';

// The rollup itself lives in `@akasecurity/schema`. These re-exports exist because
// `cli/src/tui/report.ts` reaches this module through the `./recommendations`
// subpath, so its import names must not move — `HealthStatus` keeps its historical
// name here, where schema needs an unambiguous one (a finding's `FindingStatus` is
// its lifecycle, a different thing).
export type {
  HealthStatus as FindingStatus,
  Recommendation,
  RecommendationInput,
} from '@akasecurity/schema';
export { buildRecommendations, findingStatus, healthScore } from '@akasecurity/schema';

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
