// The recommendation rollup: which detection categories most need attention, and
// how each is worded. Pure — no I/O, no React, no Node API.
//
// It lives in schema rather than beside any one renderer because FOUR surfaces
// render it and all of them must agree on the numbers: the dashboard's Recommended
// Actions card, `aka tui`'s Recommend screen, and the `/aka:recommend` output of the
// Claude Code, Codex and Antigravity plugins. The plugins cannot import the
// dashboard package, so schema is the one place all four can reach.
import type { DetectionCategory, Severity } from '../zod/finding.ts';
import type { FindingView, HealthSummary } from '../zod/local.ts';

/**
 * Descending severity weight — bigger is worse. Distinct from the private
 * `SEVERITY_ORDER` ranks in `findings-*-build.ts`, which run the other way
 * (critical = 0) and order a list rather than weigh a bucket.
 *
 * Annotated over `Severity`, so a member added there fails the build here instead
 * of weighing 0 and silently sorting last.
 */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * The same table indexed by a plain string, for the callers that hold one.
 *
 * `FindingView.severity` is `string` at this layer, so the lookups below cannot use
 * the annotated table directly. Two names over one literal is the pattern
 * `findings-group-build.ts` uses for `SEVERITY_ORDER`/`SEVERITY_RANK`: the
 * annotation buys the exhaustiveness, the alias buys the index.
 */
const SEVERITY_WEIGHT_BY_STRING = SEVERITY_WEIGHT as Partial<Record<string, number>>;

/**
 * The weight of `severity`, and 0 for one this build does not rank.
 *
 * The accessor is what is exported rather than either table, for the reason
 * {@link recommendationCopy} is: a caller holds a `string`, so indexing the
 * annotated table is a TS7053 at every call site and the cast that silences it
 * would be written once per caller. The three plugins rank their own top-findings
 * list through this.
 */
export function severityWeight(severity: string): number {
  return SEVERITY_WEIGHT_BY_STRING[severity] ?? 0;
}

// Plain-language next step per detection category, shown by the Recommend view.
//
// Annotated over `DetectionCategory` rather than `string`: a category added to the
// enum is then a compile error here, which is what stops it reaching a renderer as
// a raw `<category> finding` fallback. `code_flaw` and `config` did exactly that.
const ADVICE: Record<DetectionCategory, string> = {
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

const REC_TEMPLATE: Record<DetectionCategory, { title: string; action: string }> = {
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
    const w = severityWeight(f.severity);
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
  // Indexed through the string aliases: a finding's `category` is `string` at this
  // layer, and the fallback below is the whole point — a category this build does
  // not know must still render something.
  const template = REC_TEMPLATE_BY_STRING[category] ?? {
    title: `${category} finding`,
    action: 'Review',
  };
  return {
    ...template,
    advice: ADVICE_BY_STRING[category] ?? 'Review this finding against your policy.',
  };
}

const ADVICE_BY_STRING = ADVICE as Partial<Record<string, string>>;
const REC_TEMPLATE_BY_STRING = REC_TEMPLATE as Partial<
  Record<string, { title: string; action: string }>
>;

/**
 * The posture summary the Recommend screens head with.
 *
 * Named `HealthStatus` here, not `FindingStatus`: schema already exports that for a
 * finding's lifecycle (`open` | `handled` | `resolved` | `dismissed`), which is a
 * different thing. The renderers alias it back to their historical name, so no
 * consumer moves.
 */
export interface HealthStatus {
  score: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  openFindings: number;
}

// Derived posture score (0–100). HEURISTIC — nothing stores a posture score, so
// this blends what is on hand: category coverage (how much sensitive data is under
// an enabled policy) and the share of findings that were acted on (block/redact/
// warn) rather than let through. One implementation, so every Recommend screen and
// first-run card reads the same number and a different scoring model is one edit.
export function healthScore(summary: HealthSummary): number {
  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledRatio = summary.findings === 0 ? 1 : handled / summary.findings;
  return Math.round(100 * (0.6 * summary.coverage + 0.4 * handledRatio));
}

/**
 * The status bar's three numbers, from a whole-store health summary.
 *
 * `openFindings` is the summary's finding total and sums `bySeverity`. What is
 * passed in matters more than what comes out: every caller feeds the WHOLE-STORE
 * summary rather than the page it just fetched, so the bar reads identically across
 * surfaces whose row limits differ.
 */
export function findingStatus(summary: HealthSummary): HealthStatus {
  return {
    score: healthScore(summary),
    unreviewed: { ...summary.bySeverity },
    openFindings: summary.findings,
  };
}
