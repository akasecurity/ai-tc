// The recommendation rollup: which detection categories most need attention, and
// how each is worded. Pure — no I/O, no React, no Node API.
//
// It lives in schema rather than beside any one renderer because FOUR surfaces
// render it and every one of them must agree on the numbers: the dashboard's
// Recommended Actions card, `aka tui`'s Recommend screen, and the `/aka:recommend`
// output of the Claude Code, Codex and Antigravity plugins. Those last three cannot
// import the dashboard package, so the logic used to be copied per plugin — and the
// copies drifted, one gaining a `code_flaw` advice line the others lacked and a
// title none of them had.
import type { FindingView } from '../zod/local.ts';

/**
 * Descending severity weight — bigger is worse.
 *
 * Exported because the plugins sort their own top-findings list by it. Distinct
 * from the private `SEVERITY_ORDER` ranks in `findings-*-build.ts`, which run the
 * other way (critical = 0) and order a list rather than weigh a bucket.
 */
export const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

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

export interface Bucket {
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
export function bucketizeRecommendations(findings: RecommendationInput[]): Bucket[] {
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
  return bucketizeRecommendations(findings).map((b) => {
    const copy = recommendationCopy(b.category);
    return {
      severity: b.severity,
      title: copy.title,
      description: copy.advice,
      context: `${b.ruleId} · ${String(b.count)} finding${b.count === 1 ? '' : 's'}`,
      action: copy.action,
    };
  });
}
/** How one detection category is worded wherever it is recommended. */
export interface RecommendationCopy {
  title: string;
  action: string;
  advice: string;
}

/**
 * The copy for `category`, falling back for one this build does not know.
 *
 * A single accessor rather than two exported tables: the fallback is the case that
 * matters — a category with no entry renders a raw `<category> finding` under a
 * generic "Review", and on a store where it ranks first that is the most prominent
 * row. Resolving it in one place is what lets every surface fall back identically.
 */
export function recommendationCopy(category: string): RecommendationCopy {
  const template = REC_TEMPLATE[category] ?? { title: `${category} finding`, action: 'Review' };
  return {
    ...template,
    advice: ADVICE[category] ?? 'Review this finding against your policy.',
  };
}
